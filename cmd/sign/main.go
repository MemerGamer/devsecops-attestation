// Command sign creates a signed attestation for a security check result
// and appends it to an attestation chain file.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type signFlags struct {
	checkType   string
	tool        string
	toolVersion string
	resultFile  string
	targetRef   string
	subject     string
	signingKey  string
	signerID    string
	logEntry    string
	chain       string
	out         string
}

// scanResultInput is the JSON format read from the --result file.
type scanResultInput struct {
	Passed      bool           `json:"passed"`
	PassedCount int            `json:"passed_count"`
	Findings    []types.Finding `json:"findings"`
}

var flags signFlags

var rootCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a security check result and append it to the attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSign(cmd.Context(), flags)
	},
}

func init() {
	rootCmd.Flags().StringVar(&flags.checkType, "check-type", "", "check type: sast, sca, config, secret (required)")
	rootCmd.Flags().StringVar(&flags.tool, "tool", "", "tool name, e.g. semgrep (required)")
	rootCmd.Flags().StringVar(&flags.toolVersion, "tool-version", "unknown", "tool version")
	rootCmd.Flags().StringVar(&flags.resultFile, "result", "", "path to JSON scan result file (required)")
	rootCmd.Flags().StringVar(&flags.targetRef, "target-ref", "", "git SHA or artifact digest (required)")
	rootCmd.Flags().StringVar(&flags.subject, "subject", "", "artifact or application name (required)")
	rootCmd.Flags().StringVar(&flags.signingKey, "signing-key", "", "128-char hex Ed25519 private key (required)")
	rootCmd.Flags().StringVar(&flags.signerID, "signer-id", "", "human-readable signer identity, e.g. github-runner:ubuntu-22.04 (optional)")
	rootCmd.Flags().StringVar(&flags.logEntry, "log-entry", "", "transparency log URL or reference for this attestation (optional)")
	rootCmd.Flags().StringVar(&flags.chain, "chain", "attestation-chain.json", "path to chain file (read and write)")
	rootCmd.Flags().StringVar(&flags.out, "out", "", "write output to this path instead of --chain")

	rootCmd.MarkFlagRequired("check-type")
	rootCmd.MarkFlagRequired("tool")
	rootCmd.MarkFlagRequired("result")
	rootCmd.MarkFlagRequired("target-ref")
	rootCmd.MarkFlagRequired("subject")
	rootCmd.MarkFlagRequired("signing-key")
}

func runSign(_ context.Context, f signFlags) error {
	checkType, err := parseCheckType(f.checkType)
	if err != nil {
		return err
	}

	privBytes, err := hex.DecodeString(f.signingKey)
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

	resultData, err := os.ReadFile(f.resultFile)
	if err != nil {
		return fmt.Errorf("reading result file %s: %w", f.resultFile, err)
	}
	var input scanResultInput
	if err := json.Unmarshal(resultData, &input); err != nil {
		return fmt.Errorf("parsing result file %s: %w", f.resultFile, err)
	}

	existing, err := attestation.LoadChain(f.chain)
	if err != nil {
		return fmt.Errorf("loading chain: %w", err)
	}

	chain := attestation.NewChainFromSlice(existing)
	if f.signerID != "" {
		chain.SetNextSignerID(f.signerID)
	}
	if f.logEntry != "" {
		chain.SetNextLogEntry(f.logEntry)
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

func parseCheckType(s string) (types.SecurityCheckType, error) {
	switch s {
	case "sast":
		return types.CheckSAST, nil
	case "sca":
		return types.CheckSCA, nil
	case "config":
		return types.CheckConfig, nil
	case "secret":
		return types.CheckSecret, nil
	default:
		return "", fmt.Errorf("unknown check type %q: must be one of sast, sca, config, secret", s)
	}
}
