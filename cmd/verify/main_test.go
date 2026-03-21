package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func buildAndSaveChain(t testing.TB, dir string, n int) (chainPath string, pubHex string) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	c := attestation.NewChain()
	checkTypes := []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig}
	for i := 0; i < n; i++ {
		result := types.SecurityResult{
			CheckType: checkTypes[i%len(checkTypes)],
			Tool:      "semgrep",
			Version:   "1.0.0",
			TargetRef: "abc123",
			Findings:  []types.Finding{},
			Passed:    true,
		}
		c.Add(types.AttestationSubject{Name: "app"}, result, kp) //nolint
	}

	chainPath = filepath.Join(dir, "chain.json")
	if err := attestation.SaveChain(chainPath, c.Attestations()); err != nil {
		t.Fatalf("SaveChain() error = %v", err)
	}
	return chainPath, hex.EncodeToString([]byte(kp.PublicKey))
}

func TestRunVerify(t *testing.T) {
	t.Run("valid chain exits without error", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, _ := buildAndSaveChain(t, dir, 3)

		err := runVerify(verifyFlags{chain: chainPath})
		if err != nil {
			t.Errorf("runVerify() unexpected error = %v", err)
		}
	})

	t.Run("valid chain with matching --verify-signer succeeds", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, pubHex := buildAndSaveChain(t, dir, 2)

		err := runVerify(verifyFlags{chain: chainPath, verifySigner: pubHex})
		if err != nil {
			t.Errorf("runVerify() unexpected error = %v", err)
		}
	})

	t.Run("invalid --verify-signer hex returns error", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, _ := buildAndSaveChain(t, dir, 1)

		err := runVerify(verifyFlags{chain: chainPath, verifySigner: "not-hex!!!"})
		if err == nil {
			t.Error("runVerify() expected error for invalid signer hex, got nil")
		}
	})

	t.Run("writes JSON report when --output is set", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, _ := buildAndSaveChain(t, dir, 2)
		reportPath := filepath.Join(dir, "report.json")

		err := runVerify(verifyFlags{chain: chainPath, output: reportPath})
		if err != nil {
			t.Fatalf("runVerify() error = %v", err)
		}

		if _, err := os.Stat(reportPath); os.IsNotExist(err) {
			t.Error("report file was not created")
		}
		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		if len(data) == 0 {
			t.Error("report file is empty")
		}
	})
}
