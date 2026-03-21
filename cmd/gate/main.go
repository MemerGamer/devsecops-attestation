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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "gate",
	Short: "Evaluate an attestation chain against a deployment gate policy",
}

type evaluateFlags struct {
	chain        string
	verifySigner string
	policyFile   string
	output       string
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
	evaluateCmd.Flags().StringVar(&evalFlags.verifySigner, "verify-signer", "", "hex public key; all attestations must use this signer if set")
	evaluateCmd.Flags().StringVar(&evalFlags.policyFile, "policy", "", "path to Rego policy file (uses built-in policy if empty)")
	evaluateCmd.Flags().StringVar(&evalFlags.output, "output", "", "write GateDecision JSON to this path")

	evaluateCmd.MarkFlagRequired("chain")

	rootCmd.AddCommand(evaluateCmd)
}

func runEvaluate(ctx context.Context, f evaluateFlags) error {
	chain, err := attestation.LoadChain(f.chain)
	if err != nil {
		return fmt.Errorf("loading chain: %w", err)
	}

	// Security precondition: verify chain BEFORE policy evaluation.
	// Policy must never run on an unverified chain.
	if _, chainErr := attestation.VerifyChain(chain); chainErr != nil {
		fmt.Fprintf(os.Stderr, "chain verification failed: %v\n", chainErr)
		os.Exit(1)
	}

	// Optional signer verification.
	if f.verifySigner != "" {
		if err := verifySigner(chain, f.verifySigner); err != nil {
			fmt.Fprintf(os.Stderr, "signer verification failed: %v\n", err)
			os.Exit(1)
		}
	}

	subject := types.AttestationSubject{}
	if len(chain) > 0 {
		subject = chain[0].Subject
	}

	input := types.PolicyInput{
		Subject:      subject,
		Attestations: chain,
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
		os.Exit(1)
	}

	return nil
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
