// Command sign creates a signed attestation for a security check result
// and appends it to an attestation chain file. It also exposes normalize
// subcommands so raw tool output can be converted to the canonical result
// shape, either standalone (`attest normalize`) or inline as part of signing
// (`attest --tool-format`).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/normalize"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// version identifies the build of the attest binary. It is overridden at
// build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type signFlags struct {
	checkType      string
	tool           string
	toolFormat     string
	failOn         string
	toolVersion    string
	resultFile     string
	targetRef      string
	subject        string
	signingKey     string
	signingKeyFile string
	signerID       string
	logEntry       string
	chain          string
	out            string
	noEnvDefaults  bool
}

// scanResultInput is the JSON format read from the --result file.
type scanResultInput struct {
	Passed      bool            `json:"passed"`
	PassedCount int             `json:"passed_count"`
	Findings    []types.Finding `json:"findings"`
}

var flags signFlags

var rootCmd = &cobra.Command{
	Use:     "sign",
	Short:   "Sign a security check result and append it to the attestation chain",
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSign(cmd.Context(), flags)
	},
}

// signCmd is an explicit "sign" subcommand with the exact same flags and
// RunE as the root command. It exists because the CI workflow invokes the
// binary as `attest sign --check-type ... `: before this package gained the
// normalize and tools subcommands, the root command had none, so cobra
// treated the unrecognized "sign" token as a plain positional argument and
// ignored it. Now that subcommands exist, cobra tries to resolve "sign" as
// one and fails with "unknown command" unless it is registered here. The
// bare root form (invoking the binary with sign's flags directly, no "sign"
// token) keeps working unchanged for backward compatibility.
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a security check result and append it to the attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSign(cmd.Context(), flags)
	},
}

// registerSignFlags registers the sign flag set on cmd, binding every flag
// to the shared package-level flags variable. It is called once for the
// root command and once for the "sign" subcommand so both expose an
// identical flag set without duplicating the flag definitions themselves.
func registerSignFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flags.checkType, "check-type", "", "check type, e.g. sast, sca, config, secret, or a custom lowercase identifier (required unless --tool-format supplies a default)")
	cmd.Flags().StringVar(&flags.tool, "tool", "", "tool name, e.g. semgrep (required unless --tool-format supplies a default)")
	cmd.Flags().StringVar(&flags.toolFormat, "tool-format", "", "normalize adapter name; when set, --result is treated as raw tool output and normalized inline before signing")
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "critical", "minimum severity (inclusive) that fails inline normalization, used only with --tool-format; passed means no finding at or above this threshold, and this should match the gate's --fail-on-severity")
	cmd.Flags().StringVar(&flags.toolVersion, "tool-version", "unknown", "tool version")
	cmd.Flags().StringVar(&flags.resultFile, "result", "", "path to JSON scan result file (required)")
	cmd.Flags().StringVar(&flags.targetRef, "target-ref", "", "git SHA or artifact digest (required)")
	cmd.Flags().StringVar(&flags.subject, "subject", "", "artifact or application name (required)")
	cmd.Flags().StringVar(&flags.signingKey, "signing-key", "", "128-char hex Ed25519 private key, passed on argv (discouraged: visible in /proc/<pid>/cmdline on shared runners; prefer --signing-key-file or ATTEST_SIGNING_KEY)")
	cmd.Flags().StringVar(&flags.signingKeyFile, "signing-key-file", "", "path to a file containing the 128-char hex Ed25519 private key (whitespace trimmed)")
	cmd.Flags().StringVar(&flags.signerID, "signer-id", "", "human-readable signer identity, e.g. github-runner:ubuntu-22.04 (optional; derived from CI env vars when empty, see --no-env-defaults)")
	cmd.Flags().StringVar(&flags.logEntry, "log-entry", "", "transparency log URL or reference for this attestation (optional; derived from CI env vars when empty, see --no-env-defaults)")
	cmd.Flags().StringVar(&flags.chain, "chain", "attestation-chain.json", "path to chain file (read and write)")
	cmd.Flags().StringVar(&flags.out, "out", "", "write output to this path instead of --chain")
	cmd.Flags().BoolVar(&flags.noEnvDefaults, "no-env-defaults", false, "disable deriving --signer-id and --log-entry from CI environment variables")

	cmd.MarkFlagRequired("result")
	cmd.MarkFlagRequired("target-ref")
	cmd.MarkFlagRequired("subject")
}

func init() {
	registerSignFlags(rootCmd)
	registerSignFlags(signCmd)

	rootCmd.AddCommand(normalizeCmd)
	rootCmd.AddCommand(toolsCmd)
	rootCmd.AddCommand(signCmd)
}

// resolveToolAndCheckType validates and, when --tool-format is set, defaults
// --tool and --check-type from the adapter. Both flags stopped being
// cobra-required so this combination can be checked manually with clearer,
// tool-format-aware error messages.
func resolveToolAndCheckType(f *signFlags) error {
	if f.toolFormat == "" {
		if f.checkType == "" {
			return fmt.Errorf("required flag(s) \"check-type\" not set")
		}
		if f.tool == "" {
			return fmt.Errorf("required flag(s) \"tool\" not set")
		}
		return nil
	}

	adapter, err := normalize.Get(f.toolFormat)
	if err != nil {
		return fmt.Errorf("resolving --tool-format: %w", err)
	}

	if f.tool == "" {
		f.tool = adapter.Name()
	}

	if f.checkType == "" {
		ct := adapter.CheckType()
		if ct == "" {
			return fmt.Errorf("adapter %q has no default check type, pass --check-type explicitly", f.toolFormat)
		}
		f.checkType = ct
	}

	return nil
}

// resolveSigningKey determines the hex-encoded Ed25519 private key to sign
// with, from exactly one of three sources, in this priority order:
// --signing-key, --signing-key-file, then the ATTEST_SIGNING_KEY
// environment variable. --signing-key is kept for backward compatibility
// but is discouraged: it is visible in /proc/<pid>/cmdline for the
// process's lifetime, which matters on shared CI runners. lookup is
// injected so tests can supply a fake environment instead of mutating the
// process one.
func resolveSigningKey(f signFlags, lookup func(string) (string, bool)) (string, error) {
	haveFlag := f.signingKey != ""
	haveFile := f.signingKeyFile != ""

	if haveFlag && haveFile {
		return "", fmt.Errorf("only one of --signing-key or --signing-key-file may be set")
	}

	if haveFlag {
		return f.signingKey, nil
	}

	if haveFile {
		data, err := os.ReadFile(f.signingKeyFile)
		if err != nil {
			return "", fmt.Errorf("reading signing key file %s: %w", f.signingKeyFile, err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("signing key file %s is empty", f.signingKeyFile)
		}
		return key, nil
	}

	if envKey, ok := lookup("ATTEST_SIGNING_KEY"); ok && envKey != "" {
		return envKey, nil
	}

	return "", fmt.Errorf("signing key required: set exactly one of --signing-key, --signing-key-file, or ATTEST_SIGNING_KEY")
}

func runSign(_ context.Context, f signFlags) error {
	if err := resolveToolAndCheckType(&f); err != nil {
		return err
	}

	checkType, err := parseCheckType(f.checkType)
	if err != nil {
		return err
	}

	signingKeyHex, err := resolveSigningKey(f, os.LookupEnv)
	if err != nil {
		return err
	}

	privBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		return fmt.Errorf("decoding signing key hex: %w", err)
	}
	// Ed25519 private key embeds the public key in its last 32 bytes.
	if len(privBytes) != 64 {
		return fmt.Errorf("signing key must be 64 bytes (128 hex chars), got %d bytes", len(privBytes))
	}
	pubBytes := privBytes[32:]
	kp, err := crypto.KeyPairFromBytes(pubBytes, privBytes)
	if err != nil {
		return fmt.Errorf("loading key pair: %w", err)
	}

	input, err := loadScanResultInput(f)
	if err != nil {
		return err
	}

	existing, err := attestation.LoadChain(f.chain)
	if err != nil {
		return fmt.Errorf("loading chain: %w", err)
	}

	chain := attestation.NewChainFromSlice(existing)

	signerID := f.signerID
	logEntry := f.logEntry
	if !f.noEnvDefaults {
		envDefaults := resolveEnvDefaults(os.LookupEnv)
		if signerID == "" {
			signerID = envDefaults.signerID
		}
		if logEntry == "" {
			logEntry = envDefaults.logEntry
		}
	}
	if signerID != "" {
		chain.SetNextSignerID(signerID)
	}
	if logEntry != "" {
		chain.SetNextLogEntry(logEntry)
	}

	result := types.SecurityResult{
		CheckType:   checkType,
		Tool:        f.tool,
		Version:     f.toolVersion,
		TargetRef:   f.targetRef,
		RunAt:       time.Now().UTC(),
		PassedCount: input.PassedCount,
		Findings:    input.Findings,
		Passed:      input.Passed,
	}
	if result.Findings == nil {
		result.Findings = []types.Finding{}
	}

	subject := types.AttestationSubject{Name: f.subject}

	a, err := chain.Add(subject, result, kp)
	if err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	outPath := f.chain
	if f.out != "" {
		outPath = f.out
	}
	if err := attestation.SaveChain(outPath, chain.Attestations()); err != nil {
		return fmt.Errorf("saving chain: %w", err)
	}

	fmt.Println(a.ID)
	return nil
}

// loadScanResultInput reads --result. When --tool-format is set, the file is
// treated as raw tool output and normalized inline via pkg/normalize;
// otherwise it is parsed directly as the canonical scanResultInput shape.
func loadScanResultInput(f signFlags) (scanResultInput, error) {
	file, err := os.Open(f.resultFile)
	if err != nil {
		return scanResultInput{}, fmt.Errorf("reading result file %s: %w", f.resultFile, err)
	}
	defer file.Close()

	if f.toolFormat == "" {
		var input scanResultInput
		if err := json.NewDecoder(file).Decode(&input); err != nil {
			return scanResultInput{}, fmt.Errorf("parsing result file %s: %w", f.resultFile, err)
		}
		if err := validateCanonicalSeverities(input.Findings); err != nil {
			return scanResultInput{}, err
		}
		return input, nil
	}

	failOn, err := normalize.ParseSeverity(f.failOn)
	if err != nil {
		return scanResultInput{}, fmt.Errorf("parsing --fail-on: %w", err)
	}

	result, err := normalize.Run(f.toolFormat, file, failOn)
	if err != nil {
		return scanResultInput{}, fmt.Errorf("normalizing %s: %w", f.resultFile, err)
	}

	return scanResultInput{
		Passed:      result.Passed,
		PassedCount: result.PassedCount,
		Findings:    result.Findings,
	}, nil
}

// validateCanonicalSeverities rejects any finding whose severity is not
// exactly one of the five canonical lowercase values. It is only applied to
// the non-normalized --result path (--tool-format unset): a raw tool report
// normalized inline via pkg/normalize already validates and rewrites
// severities to their canonical form, but a hand-authored or externally
// produced --result file bypasses that path entirely, so nothing otherwise
// checks its severity spelling before it is signed into the attestation
// chain.
func validateCanonicalSeverities(findings []types.Finding) error {
	for i, f := range findings {
		switch f.Severity {
		case types.SeverityInfo, types.SeverityLow, types.SeverityMedium, types.SeverityHigh, types.SeverityCritical:
			continue
		default:
			return fmt.Errorf("finding %d (id %q) has non-canonical severity %q: --result must use exactly one of info, low, medium, high, critical - use --tool-format generic or `attest normalize` to convert raw tool output first", i, f.ID, f.Severity)
		}
	}
	return nil
}

func parseCheckType(s string) (types.SecurityCheckType, error) {
	if err := types.ValidateCheckType(s); err != nil {
		return "", err
	}
	return types.SecurityCheckType(s), nil
}

// envDefaults holds the CI-derived defaults for --signer-id and --log-entry.
type envDefaults struct {
	signerID string
	logEntry string
}

// resolveEnvDefaults derives forge-portable defaults for --signer-id and
// --log-entry from CI environment variables (WP1.5). lookup is injected so
// tests can supply a fake environment instead of mutating the process one.
//
// GITHUB_SERVER_URL is set by both GitHub Actions and Forgejo Actions runners,
// so this derivation is portable across both without a forge-specific branch.
//
// signer-id is only derived when all four of GITHUB_SERVER_URL,
// GITHUB_REPOSITORY, GITHUB_WORKFLOW and GITHUB_JOB are non-empty. Deriving
// it from a partial set would silently embed empty segments (e.g.
// ":::job"), which looks plausible but is not a meaningful signer identity.
func resolveEnvDefaults(lookup func(string) (string, bool)) envDefaults {
	serverURL, _ := lookup("GITHUB_SERVER_URL")
	repo, _ := lookup("GITHUB_REPOSITORY")
	workflow, _ := lookup("GITHUB_WORKFLOW")
	job, _ := lookup("GITHUB_JOB")
	runID, _ := lookup("GITHUB_RUN_ID")

	var out envDefaults

	if serverURL != "" && repo != "" && workflow != "" && job != "" {
		host := stripScheme(serverURL)
		out.signerID = fmt.Sprintf("%s:%s:%s:%s", host, repo, workflow, job)
	}

	if serverURL != "" && repo != "" && runID != "" {
		out.logEntry = fmt.Sprintf("%s/%s/actions/runs/%s", serverURL, repo, runID)
	}

	return out
}

// stripScheme removes a leading "scheme://" from a URL, e.g.
// "https://github.com" -> "github.com". Strings without a scheme are
// returned unchanged.
func stripScheme(url string) string {
	if idx := strings.Index(url, "://"); idx >= 0 {
		return url[idx+len("://"):]
	}
	return url
}

// normalizeFlags holds the flags for `attest normalize`.
type normalizeFlags struct {
	tool   string
	in     string
	out    string
	failOn string
}

var normalizeFlagsVar normalizeFlags

var normalizeCmd = &cobra.Command{
	Use:   "normalize",
	Short: "Normalize a raw security tool report into the canonical result shape",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runNormalize(normalizeFlagsVar)
	},
}

func init() {
	normalizeCmd.Flags().StringVar(&normalizeFlagsVar.tool, "tool", "", "normalize adapter name, e.g. semgrep (required)")
	normalizeCmd.Flags().StringVar(&normalizeFlagsVar.in, "in", "", "path to raw tool report, or - to read from stdin (required)")
	normalizeCmd.Flags().StringVar(&normalizeFlagsVar.out, "out", "", "write canonical JSON to this path instead of stdout")
	normalizeCmd.Flags().StringVar(&normalizeFlagsVar.failOn, "fail-on", "critical", "minimum severity (inclusive) that fails the run; passed means no finding at or above this threshold, and this should match the gate's --fail-on-severity")

	normalizeCmd.MarkFlagRequired("tool")
	normalizeCmd.MarkFlagRequired("in")
}

func runNormalize(f normalizeFlags) error {
	var r io.Reader
	if f.in == "-" {
		r = os.Stdin
	} else {
		file, err := os.Open(f.in)
		if err != nil {
			return fmt.Errorf("reading input file %s: %w", f.in, err)
		}
		defer file.Close()
		r = file
	}

	failOn, err := normalize.ParseSeverity(f.failOn)
	if err != nil {
		return fmt.Errorf("parsing --fail-on: %w", err)
	}

	result, err := normalize.Run(f.tool, r, failOn)
	if err != nil {
		return fmt.Errorf("normalizing %s: %w", f.in, err)
	}

	data, err := result.MarshalIndent()
	if err != nil {
		return fmt.Errorf("encoding result: %w", err)
	}

	if f.out == "" {
		fmt.Println(string(data))
		return nil
	}

	if err := os.WriteFile(f.out, data, 0o644); err != nil {
		return fmt.Errorf("writing output file %s: %w", f.out, err)
	}
	return nil
}

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "List registered normalize adapters",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTools()
	},
}

func runTools() error {
	for _, name := range normalize.Names() {
		adapter, err := normalize.Get(name)
		if err != nil {
			return fmt.Errorf("looking up adapter %q: %w", name, err)
		}
		checkType := adapter.CheckType()
		if checkType == "" {
			checkType = "-"
		}
		fmt.Printf("%s\t%s\n", name, checkType)
	}
	return nil
}
