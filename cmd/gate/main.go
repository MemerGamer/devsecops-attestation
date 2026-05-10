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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// osExit is a variable so tests can intercept os.Exit calls.
var osExit = os.Exit

func main() {
	if err := rootCmd.Execute(); err != nil {
		osExit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "gate",
	Short: "Evaluate an attestation chain against a deployment gate policy",
}

type evaluateFlags struct {
	chain               string
	verifySigner        string
	policyFile          string
	policyHash          string
	authorizedSigners   string
	output              string
	maxAge              string
	requireLogEntries   bool
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
	evaluateCmd.Flags().StringVar(&evalFlags.policyHash, "policy-hash", "", "expected SHA-256 hex of the policy file; requires --policy")
	evaluateCmd.Flags().StringVar(&evalFlags.authorizedSigners, "authorized-signers", "", "check-type=hex pairs e.g. sast=<hex>,sca=<hex>")
	evaluateCmd.Flags().StringVar(&evalFlags.output, "output", "", "write GateDecision JSON to this path")
	evaluateCmd.Flags().StringVar(&evalFlags.maxAge, "max-age", "", "maximum allowed attestation age, e.g. 24h (no limit if empty)")
	evaluateCmd.Flags().BoolVar(&evalFlags.requireLogEntries, "require-log-entries", false, "fail if any attestation lacks a transparency log entry")

	evaluateCmd.MarkFlagRequired("chain")

	rootCmd.AddCommand(evaluateCmd)
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

	// Policy file integrity: verify SHA-256 hash before loading the policy.
	if f.policyHash != "" {
		if f.policyFile == "" {
			return fmt.Errorf("--policy-hash requires --policy: built-in policy has no file to hash")
		}
		data, err := os.ReadFile(f.policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file for hash verification: %w", err)
		}
		sum := sha256.Sum256(data)
		actual := hex.EncodeToString(sum[:])
		if actual != strings.ToLower(f.policyHash) {
			return fmt.Errorf("policy file hash mismatch: expected %s, got %s", strings.ToLower(f.policyHash), actual)
		}
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

	decision, err := policy.EvaluateFromFile(ctx, f.policyFile, input)
	if err != nil {
		return fmt.Errorf("evaluating policy: %w", err)
	}

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
