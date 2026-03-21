// Command verify loads an attestation chain and verifies all signatures
// and chain linkage, reporting per-attestation results.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type verifyFlags struct {
	chain        string
	verifySigner string
	output       string
}

// verifyReport is the JSON structure written to --output.
type verifyReport struct {
	ChainValid       bool              `json:"chain_valid"`
	AttestationCount int               `json:"attestation_count"`
	Results          []verifyResult    `json:"results"`
}

type verifyResult struct {
	ID             string `json:"id"`
	CheckType      string `json:"check_type"`
	SignatureValid bool   `json:"signature_valid"`
	ChainValid     bool   `json:"chain_valid"`
	Error          string `json:"error,omitempty"`
}

var flags verifyFlags

var rootCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the signature and chain integrity of an attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVerify(flags)
	},
}

func init() {
	rootCmd.Flags().StringVar(&flags.chain, "chain", "", "path to chain JSON file (required)")
	rootCmd.Flags().StringVar(&flags.verifySigner, "verify-signer", "", "hex public key; all attestations must use this signer if set")
	rootCmd.Flags().StringVar(&flags.output, "output", "", "write JSON report to this path")

	rootCmd.MarkFlagRequired("chain")
}

func runVerify(f verifyFlags) error {
	chain, err := attestation.LoadChain(f.chain)
	if err != nil {
		return fmt.Errorf("loading chain: %w", err)
	}

	results, chainErr := attestation.VerifyChain(chain)

	// Optional signer check.
	if f.verifySigner != "" {
		expectedPub, err := hex.DecodeString(f.verifySigner)
		if err != nil {
			return fmt.Errorf("decoding --verify-signer hex: %w", err)
		}
		for i, a := range chain {
			if !bytes.Equal(a.SignerPublicKey, expectedPub) {
				msg := fmt.Sprintf("attestation %d (%s): signer public key does not match --verify-signer", i, a.ID)
				if chainErr == nil {
					chainErr = fmt.Errorf("%s", msg)
				}
				if i < len(results) {
					results[i].SignatureValid = false
					results[i].Error = fmt.Errorf("%s", msg)
				}
			}
		}
	}

	// Build report.
	report := verifyReport{
		ChainValid:       chainErr == nil,
		AttestationCount: len(results),
		Results:          make([]verifyResult, len(results)),
	}
	for i, r := range results {
		vr := verifyResult{
			ID:             r.AttestationID,
			CheckType:      r.CheckType,
			SignatureValid: r.SignatureValid,
			ChainValid:     r.ChainValid,
		}
		if r.Error != nil {
			vr.Error = r.Error.Error()
		}
		report.Results[i] = vr
	}

	// Print human-readable summary.
	for _, r := range report.Results {
		status := "OK"
		if !r.SignatureValid || !r.ChainValid {
			status = "FAIL"
		}
		fmt.Printf("[%s] %s (%s)\n", status, r.ID, r.CheckType)
		if r.Error != "" {
			fmt.Printf("       error: %s\n", r.Error)
		}
	}

	if f.output != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling report: %w", err)
		}
		if err := os.WriteFile(f.output, data, 0o644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	if chainErr != nil {
		fmt.Fprintf(os.Stderr, "chain verification failed: %v\n", chainErr)
		os.Exit(1)
	}
	return nil
}
