// Command gate evaluates a verified attestation chain against a Rego policy
// and produces a deployment gate decision (allow / block).
//
// Security precondition: chain verification always runs before policy evaluation.
// A broken chain causes exit 1 without evaluating the policy. This ensures the
// policy is never evaluated on unverified (potentially tampered) data.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// osExit is a variable so tests can intercept os.Exit calls.
var osExit = os.Exit

// version identifies the build of the gate binary. It is overridden at
// build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		osExit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:     "gate",
	Short:   "Evaluate an attestation chain against a deployment gate policy",
	Version: version,
}

type evaluateFlags struct {
	chain               string
	verifySigner        string
	policyFile          string
	policyHash          string
	configHash          string
	authorizedSigners   string
	output              string
	maxAge              string
	requireLogEntries   bool
	requiredChecks      string
	failOnSeverity      string
	zeroToleranceChecks string
	dataFile            string
	targetRef           string
	subject             string
}

// validSeverities are the severity levels accepted by --fail-on-severity,
// mirroring the ordering used by the bundled policy's severity_rank table.
var validSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var evalFlags evaluateFlags

var evaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Run the gate policy against an attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEvaluate(cmd.Context(), evalFlags)
	},
}

func init() {
	evaluateCmd.Flags().StringVar(&evalFlags.chain, "chain", "", "path to chain JSON file (required)")
	evaluateCmd.Flags().StringVar(&evalFlags.verifySigner, "verify-signer", "", "hex public key that all attestations must be signed with (required)")
	evaluateCmd.Flags().StringVar(&evalFlags.policyFile, "policy", "", "path to Rego policy file (uses built-in policy if empty)")
	evaluateCmd.Flags().StringVar(&evalFlags.policyHash, "policy-hash", "", "expected SHA-256 hex of the policy that will be evaluated; checked against the file given by --policy, or against the bundled default policy when --policy is empty")
	evaluateCmd.Flags().StringVar(&evalFlags.configHash, "config-hash", "", "expected SHA-256 hex of the effective policy configuration (see \"gate config-hash\"); required when --policy-hash is set and the effective config is not the bundled policy's defaults")
	evaluateCmd.Flags().StringVar(&evalFlags.authorizedSigners, "authorized-signers", "", "check-type=hex pairs e.g. sast=<hex>,sca=<hex>")
	evaluateCmd.Flags().StringVar(&evalFlags.output, "output", "", "write GateDecision JSON to this path")
	evaluateCmd.Flags().StringVar(&evalFlags.maxAge, "max-age", "", "maximum allowed attestation age, e.g. 24h (no limit if empty)")
	evaluateCmd.Flags().BoolVar(&evalFlags.requireLogEntries, "require-log-entries", false, "fail if any attestation lacks a transparency log entry")
	evaluateCmd.Flags().StringVar(&evalFlags.requiredChecks, "required-checks", "", "comma-separated required check types, e.g. sast,sca,config,secret (overrides data.config.required_checks)")
	evaluateCmd.Flags().StringVar(&evalFlags.failOnSeverity, "fail-on-severity", "", "minimum finding severity that blocks deployment: info, low, medium, high, or critical (overrides data.config.fail_on_severity)")
	evaluateCmd.Flags().StringVar(&evalFlags.zeroToleranceChecks, "zero-tolerance-checks", "", "comma-separated check types with zero finding tolerance, e.g. secret (overrides data.config.zero_tolerance_checks)")
	evaluateCmd.Flags().StringVar(&evalFlags.dataFile, "data", "", "path to a JSON file whose object becomes data.config for policy evaluation; --required-checks, --fail-on-severity, and --zero-tolerance-checks override its keys")
	evaluateCmd.Flags().StringVar(&evalFlags.targetRef, "target-ref", "", "commit or artifact digest that every attestation's result.target_ref must equal (commit binding); empty disables the check")
	evaluateCmd.Flags().StringVar(&evalFlags.subject, "subject", "", "subject name that every attestation's subject.name must equal; empty disables the check")

	evaluateCmd.MarkFlagRequired("chain")

	rootCmd.AddCommand(evaluateCmd)
	rootCmd.AddCommand(policyHashCmd)
	rootCmd.AddCommand(configHashCmd)
}

type policyHashFlags struct {
	policyFile string
}

var policyHashFlagsVar policyHashFlags

var policyHashCmd = &cobra.Command{
	Use:   "policy-hash",
	Short: "Print the SHA-256 hex hash of a Rego policy file (or the bundled default policy)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPolicyHash(policyHashFlagsVar)
	},
}

func init() {
	policyHashCmd.Flags().StringVar(&policyHashFlagsVar.policyFile, "policy", "", "path to Rego policy file (hashes the built-in policy if empty)")
}

// runPolicyHash prints the hex-encoded SHA-256 of the given policy file, or
// of the bundled default policy when no file is given. It uses the same
// hashing that --policy-hash checks in "gate evaluate" against.
func runPolicyHash(f policyHashFlags) error {
	var data []byte
	if f.policyFile == "" {
		data = []byte(policy.DefaultPolicy)
	} else {
		b, err := os.ReadFile(f.policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		data = b
	}
	sum := sha256.Sum256(data)
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

type configHashFlags struct {
	dataFile            string
	requiredChecks      string
	failOnSeverity      string
	zeroToleranceChecks string
}

var configHashFlagsVar configHashFlags

var configHashCmd = &cobra.Command{
	Use:   "config-hash",
	Short: "Print the SHA-256 hex hash of the effective policy configuration",
	Long: "Print the SHA-256 hex hash of the effective data.config that " +
		"\"gate evaluate\" would use for the given --data / --required-checks " +
		"/ --fail-on-severity / --zero-tolerance-checks combination, with " +
		"defaults filled in explicitly. Pass the result to " +
		"\"gate evaluate --config-hash\" to pin the configuration alongside " +
		"--policy-hash.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigHash(configHashFlagsVar)
	},
}

func init() {
	configHashCmd.Flags().StringVar(&configHashFlagsVar.dataFile, "data", "", "path to a JSON file whose object becomes data.config for policy evaluation")
	configHashCmd.Flags().StringVar(&configHashFlagsVar.requiredChecks, "required-checks", "", "comma-separated required check types, e.g. sast,sca,config,secret (overrides data.config.required_checks)")
	configHashCmd.Flags().StringVar(&configHashFlagsVar.failOnSeverity, "fail-on-severity", "", "minimum finding severity that blocks deployment: info, low, medium, high, or critical (overrides data.config.fail_on_severity)")
	configHashCmd.Flags().StringVar(&configHashFlagsVar.zeroToleranceChecks, "zero-tolerance-checks", "", "comma-separated check types with zero finding tolerance, e.g. secret (overrides data.config.zero_tolerance_checks)")
}

// runConfigHash prints the hex-encoded SHA-256 of the effective policy
// configuration built from the same --data / override flags "gate evaluate"
// accepts. It uses the same resolution logic runEvaluate uses to compute
// the config hash that --config-hash checks against.
func runConfigHash(f configHashFlags) error {
	overrides, err := loadPolicyConfig(evaluateFlags{
		dataFile:            f.dataFile,
		requiredChecks:      f.requiredChecks,
		failOnSeverity:      f.failOnSeverity,
		zeroToleranceChecks: f.zeroToleranceChecks,
	})
	if err != nil {
		return fmt.Errorf("loading policy configuration: %w", err)
	}

	effective := buildEffectiveConfig(overrides)
	hash, err := hashEffectiveConfig(effective)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}

// defaultRequiredChecks, defaultFailOnSeverity, and defaultZeroToleranceChecks
// mirror the bundled policy's own defaults (policies/deploy.rego). They are
// used to fill in the effective configuration explicitly whenever a
// parameter is not overridden, so --config-hash covers the full set of
// parameters the policy reads, not only the ones a caller happened to pass.
var (
	defaultRequiredChecks      = []string{"config", "sast", "sca", "secret"}
	defaultFailOnSeverity      = "high"
	defaultZeroToleranceChecks = []string{"secret"}
)

// buildEffectiveConfig resolves the full data.config object that the policy
// will actually see: every parameter is present, using the override from
// overrides when given and the bundled policy's default otherwise. Lists
// are sorted so the resulting hash is stable regardless of the order the
// caller supplied entries in (the policy treats them as sets).
func buildEffectiveConfig(overrides map[string]any) map[string]any {
	required := append([]string(nil), defaultRequiredChecks...)
	if v, ok := overrides["required_checks"]; ok {
		required = toStringSlice(v)
	}
	failOn := defaultFailOnSeverity
	if v, ok := overrides["fail_on_severity"]; ok {
		if s, ok := v.(string); ok {
			failOn = s
		}
	}
	zeroTolerance := append([]string(nil), defaultZeroToleranceChecks...)
	if v, ok := overrides["zero_tolerance_checks"]; ok {
		zeroTolerance = toStringSlice(v)
	}

	sort.Strings(required)
	sort.Strings(zeroTolerance)

	return map[string]any{
		"required_checks":       required,
		"fail_on_severity":      failOn,
		"zero_tolerance_checks": zeroTolerance,
	}
}

// toStringSlice normalizes a []string or []interface{} (as produced by
// json.Unmarshal into map[string]any) into a []string. Any non-string
// element is skipped; callers only reach here with already-validated data.
func toStringSlice(v any) []string {
	switch vv := v.(type) {
	case []string:
		out := make([]string, len(vv))
		copy(out, vv)
		return out
	case []interface{}:
		out := make([]string, 0, len(vv))
		for _, elem := range vv {
			if s, ok := elem.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// hashEffectiveConfig returns the hex-encoded SHA-256 of cfg's canonical
// JSON encoding. Go's encoding/json sorts map string keys alphabetically,
// and buildEffectiveConfig sorts every list value, so the result is stable
// regardless of the order overrides were supplied in.
func hashEffectiveConfig(cfg map[string]any) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshalling effective config: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func runEvaluate(ctx context.Context, f evaluateFlags) error {
	// Zero-trust: every signer must be explicitly authorized before evaluation.
	// Accept either a single --verify-signer key (all attestations use the same key)
	// or --authorized-signers covering every check type present in the chain.
	if f.verifySigner == "" && f.authorizedSigners == "" {
		return fmt.Errorf("either --verify-signer or --authorized-signers is required: all attestation signers must be explicitly authorized")
	}

	// Parse authorized signers early so format errors surface before chain I/O.
	authorizedSigners, err := parseAuthorizedSigners(f.authorizedSigners)
	if err != nil {
		return fmt.Errorf("parsing --authorized-signers: %w", err)
	}

	// Parse the policy data.config overrides early so format errors surface
	// before chain I/O, matching the other flag validations above.
	policyConfig, err := loadPolicyConfig(f)
	if err != nil {
		return fmt.Errorf("loading policy configuration: %w", err)
	}

	chain, err := attestation.LoadChain(f.chain)
	if err != nil {
		return fmt.Errorf("loading chain: %w", err)
	}

	// Parse optional max-age constraint.
	opts := attestation.VerifyOptions{}
	if f.maxAge != "" {
		d, err := time.ParseDuration(f.maxAge)
		if err != nil {
			return fmt.Errorf("parsing --max-age: %w", err)
		}
		opts.MaxAge = d
	}

	// Security precondition: verify chain BEFORE policy evaluation.
	// Policy must never run on an unverified chain.
	if _, chainErr := attestation.VerifyChainWithOptions(chain, opts); chainErr != nil {
		fmt.Fprintf(os.Stderr, "chain verification failed: %v\n", chainErr)
		osExit(1)
		return nil
	}

	// Go-level signer authorization: enforced before policy evaluation so that
	// a misconfigured or missing policy cannot bypass key authorization.
	if f.verifySigner != "" {
		if err := verifySigner(chain, f.verifySigner); err != nil {
			fmt.Fprintf(os.Stderr, "signer verification failed: %v\n", err)
			osExit(1)
			return nil
		}
	} else {
		// Per-check-type mode: every check type in the chain must have a
		// corresponding authorized signer and the keys must match.
		if err := verifyAuthorizedSignersCoverage(chain, authorizedSigners); err != nil {
			fmt.Fprintf(os.Stderr, "authorized signer verification failed: %v\n", err)
			osExit(1)
			return nil
		}
	}

	// Commit binding: when --target-ref is given, every attestation's
	// result.target_ref must equal it exactly. VerifyChainWithOptions above
	// already rejects a chain whose attestations disagree with each other on
	// target_ref, but that alone does not stop an attacker from replaying an
	// internally-consistent chain that was produced against a different
	// commit than the one about to be deployed. Binding to the caller's
	// expected ref closes that gap. Enforced in Go, after signer
	// authorization and before policy evaluation, so an unbound or
	// mis-bound chain never reaches OPA.
	if f.targetRef != "" {
		for i, a := range chain {
			if a.Result.TargetRef != f.targetRef {
				fmt.Fprintf(os.Stderr, "target ref mismatch for attestation %d (%s, check_type=%s): got %q, want %q\n",
					i, a.ID, a.Result.CheckType, a.Result.TargetRef, f.targetRef)
				osExit(1)
				return nil
			}
		}
	}

	// Subject binding: when --subject is given, every attestation's
	// subject.name must equal it exactly.
	if f.subject != "" {
		for i, a := range chain {
			if a.Subject.Name != f.subject {
				fmt.Fprintf(os.Stderr, "subject mismatch for attestation %d (%s, check_type=%s): got %q, want %q\n",
					i, a.ID, a.Result.CheckType, a.Subject.Name, f.subject)
				osExit(1)
				return nil
			}
		}
	}

	// Transparency log enforcement: every attestation must carry a log entry
	// reference when --require-log-entries is set.
	if f.requireLogEntries {
		for i, a := range chain {
			if a.LogEntry == "" {
				fmt.Fprintf(os.Stderr, "log entry missing for attestation %d (%s, check_type=%s)\n",
					i, a.ID, a.Result.CheckType)
				osExit(1)
				return nil
			}
		}
	}

	// Policy source of truth: read the policy exactly once, whether from a
	// file or the bundled default. The hash check below and the evaluator
	// both use this same in-memory copy, so there is no window between
	// hashing and evaluating in which the on-disk file could be swapped
	// (TOCTOU). When --policy is empty, the bundled default policy is used,
	// so --policy-hash can pin the built-in policy too.
	var policySource string
	if f.policyFile == "" {
		policySource = policy.DefaultPolicy
	} else {
		data, err := os.ReadFile(f.policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		policySource = string(data)
	}

	// Policy file integrity: verify SHA-256 hash of the bytes that will
	// actually be evaluated.
	if f.policyHash != "" {
		sum := sha256.Sum256([]byte(policySource))
		actual := hex.EncodeToString(sum[:])
		if actual != strings.ToLower(f.policyHash) {
			return fmt.Errorf("policy file hash mismatch: expected %s, got %s", strings.ToLower(f.policyHash), actual)
		}
	}

	// Policy configuration integrity: compute the fully-resolved effective
	// config (defaults filled in explicitly) and its hash. This closes the
	// gap where --policy-hash pinned the policy's logic but left its
	// parameters (fail_on_severity, required_checks, zero_tolerance_checks)
	// unpinned. If the policy is pinned and the effective config is not the
	// bundled policy's defaults, --config-hash must also be given: pinning
	// the policy logic while leaving a non-default configuration unpinned is
	// a misconfiguration, not a safe default.
	effectiveConfig := buildEffectiveConfig(policyConfig)
	computedConfigHash, err := hashEffectiveConfig(effectiveConfig)
	if err != nil {
		return fmt.Errorf("computing effective config hash: %w", err)
	}
	configIsDefault := reflect.DeepEqual(effectiveConfig, buildEffectiveConfig(nil))

	if f.policyHash != "" && !configIsDefault && f.configHash == "" {
		return fmt.Errorf("policy hash is pinned and the effective policy configuration is not the bundled defaults, but --config-hash was not given: pinning policy logic without pinning a non-default configuration is a misconfiguration")
	}

	if f.configHash != "" && strings.ToLower(f.configHash) != computedConfigHash {
		return fmt.Errorf("config hash mismatch: expected %s, got %s", strings.ToLower(f.configHash), computedConfigHash)
	}

	subject := types.AttestationSubject{}
	if len(chain) > 0 {
		subject = chain[0].Subject
	}

	input := types.PolicyInput{
		Subject:           subject,
		Attestations:      chain,
		AuthorizedSigners: authorizedSigners,
	}

	decision, err := policy.NewEvaluator(policySource, policy.WithData(policyConfig)).Evaluate(ctx, input)
	if err != nil {
		return fmt.Errorf("evaluating policy: %w", err)
	}
	decision.EffectiveConfig = effectiveConfig
	decision.ConfigHash = computedConfigHash

	if f.output != "" {
		data, err := json.MarshalIndent(decision, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling decision: %w", err)
		}
		if err := os.WriteFile(f.output, data, 0o644); err != nil {
			return fmt.Errorf("writing decision: %w", err)
		}
	}

	if decision.Allow {
		fmt.Println("gate: ALLOW")
		for _, r := range decision.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	} else {
		fmt.Fprintln(os.Stderr, "gate: BLOCK")
		for _, r := range decision.Reasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		osExit(1)
		return nil
	}

	return nil
}

// loadPolicyConfig builds the data.config object passed to the OPA policy.
// It starts from --data (a JSON file, if given), then --required-checks,
// --fail-on-severity, and --zero-tolerance-checks override the corresponding
// keys when set. The result is nil when no configuration was supplied,
// leaving data.config undefined so the policy's own defaults apply.
func loadPolicyConfig(f evaluateFlags) (map[string]any, error) {
	var config map[string]any

	if f.dataFile != "" {
		b, err := os.ReadFile(f.dataFile)
		if err != nil {
			return nil, fmt.Errorf("reading --data file: %w", err)
		}
		if err := json.Unmarshal(b, &config); err != nil {
			return nil, fmt.Errorf("parsing --data file as json: %w", err)
		}
		if err := validateDataConfig(config); err != nil {
			return nil, fmt.Errorf("validating --data file: %w", err)
		}
	}

	if f.requiredChecks != "" {
		list, err := parseCommaList(f.requiredChecks)
		if err != nil {
			return nil, fmt.Errorf("parsing --required-checks: %w", err)
		}
		if config == nil {
			config = map[string]any{}
		}
		config["required_checks"] = list
	}

	if f.failOnSeverity != "" {
		sev := strings.ToLower(strings.TrimSpace(f.failOnSeverity))
		if !validSeverities[sev] {
			return nil, fmt.Errorf("invalid --fail-on-severity %q: must be one of info, low, medium, high, critical", sev)
		}
		if config == nil {
			config = map[string]any{}
		}
		config["fail_on_severity"] = sev
	}

	if f.zeroToleranceChecks != "" {
		list, err := parseCommaList(f.zeroToleranceChecks)
		if err != nil {
			return nil, fmt.Errorf("parsing --zero-tolerance-checks: %w", err)
		}
		if config == nil {
			config = map[string]any{}
		}
		config["zero_tolerance_checks"] = list
	}

	return config, nil
}

// parseCommaList splits a comma-separated flag value into a slice of
// lowercased, trimmed entries, each of which must be a syntactically valid
// check type (see types.ValidateCheckType). This rejects empty entries
// (including an entirely empty or whitespace-only flag value) the same way
// an invalid check type is rejected.
func parseCommaList(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.ToLower(strings.TrimSpace(p))
		if err := types.ValidateCheckType(v); err != nil {
			return nil, fmt.Errorf("invalid check type %q in list %q: %w", p, s, err)
		}
		result = append(result, v)
	}
	return result, nil
}

// allowedConfigKeys are the only keys the bundled policy reads from
// data.config. A --data file containing any other key is rejected rather
// than silently ignored, since a typo in a key name would otherwise leave
// the intended override unapplied.
var allowedConfigKeys = map[string]bool{
	"required_checks":       true,
	"fail_on_severity":      true,
	"zero_tolerance_checks": true,
}

// validateDataConfig validates a --data file's decoded object the same way
// the --required-checks, --fail-on-severity, and --zero-tolerance-checks
// flags are validated: unknown keys are rejected, fail_on_severity must be
// a known severity level, and required_checks / zero_tolerance_checks must
// each be a non-empty array of strings that pass types.ValidateCheckType.
// This closes the fail-open gap where a malformed --data value reached the
// policy unchecked and made the corresponding Rego rule undefined instead
// of denying.
func validateDataConfig(config map[string]any) error {
	for key := range config {
		if !allowedConfigKeys[key] {
			return fmt.Errorf("unknown policy configuration key %q", key)
		}
	}

	if v, ok := config["fail_on_severity"]; ok {
		sev, isString := v.(string)
		if !isString || !validSeverities[sev] {
			return fmt.Errorf("invalid fail_on_severity %v: must be one of info, low, medium, high, critical", v)
		}
	}

	if v, ok := config["required_checks"]; ok {
		if err := validateCheckTypeList("required_checks", v); err != nil {
			return err
		}
	}

	if v, ok := config["zero_tolerance_checks"]; ok {
		if err := validateCheckTypeList("zero_tolerance_checks", v); err != nil {
			return err
		}
	}

	return nil
}

// validateCheckTypeList validates that v (the decoded JSON value of a
// required_checks or zero_tolerance_checks key) is a non-empty array of
// strings, each a syntactically valid check type.
func validateCheckTypeList(field string, v any) error {
	list, ok := v.([]interface{})
	if !ok || len(list) == 0 {
		return fmt.Errorf("invalid %s: must be a non-empty array of strings", field)
	}
	for _, elem := range list {
		s, ok := elem.(string)
		if !ok {
			return fmt.Errorf("invalid %s: must be a non-empty array of strings", field)
		}
		if err := types.ValidateCheckType(s); err != nil {
			return fmt.Errorf("invalid %s entry: %w", field, err)
		}
	}
	return nil
}

// parseAuthorizedSigners parses a comma-separated list of check_type=hex_pubkey pairs.
// Returns an empty map for an empty input string.
func parseAuthorizedSigners(s string) (map[string]string, error) {
	result := make(map[string]string)
	if s == "" {
		return result, nil
	}
	for _, pair := range strings.Split(s, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid pair %q: expected check_type=hex_pubkey", pair)
		}
		checkType := strings.ToLower(strings.TrimSpace(parts[0]))
		hexKey := strings.ToLower(strings.TrimSpace(parts[1]))
		if _, err := hex.DecodeString(hexKey); err != nil {
			return nil, fmt.Errorf("invalid hex pubkey for check type %q: %w", checkType, err)
		}
		result[checkType] = hexKey
	}
	return result, nil
}

func verifySigner(chain []types.Attestation, signerHex string) error {
	expected, err := hex.DecodeString(signerHex)
	if err != nil {
		return fmt.Errorf("decoding --verify-signer hex: %w", err)
	}
	for i, a := range chain {
		if !bytes.Equal(a.SignerPublicKey, expected) {
			return fmt.Errorf("attestation %d (%s): signer does not match --verify-signer", i, a.ID)
		}
	}
	return nil
}

// verifyAuthorizedSignersCoverage checks that every attestation in the chain
// was signed by the key authorized for its check type in the provided map.
// Every check type present in the chain must have a corresponding entry;
// unconfigured check types are rejected to prevent authorization gaps.
func verifyAuthorizedSignersCoverage(chain []types.Attestation, authorized map[string]string) error {
	for i, a := range chain {
		checkType := string(a.Result.CheckType)
		expectedHex, ok := authorized[checkType]
		if !ok {
			return fmt.Errorf("attestation %d (%s): no authorized signer configured for check type %q",
				i, a.ID, checkType)
		}
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("decoding authorized signer hex for check type %q: %w", checkType, err)
		}
		if !bytes.Equal(a.SignerPublicKey, expected) {
			return fmt.Errorf("attestation %d (%s): signer does not match authorized signer for check type %q",
				i, a.ID, checkType)
		}
	}
	return nil
}
