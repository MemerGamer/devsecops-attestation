package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// withMockExit replaces osExit for the duration of fn, capturing the exit code.
// It uses runtime.Goexit in a goroutine so the function body stops at the mock
// os.Exit call without terminating the test process.
func withMockExit(fn func()) int {
	code := 0
	saved := osExit
	osExit = func(c int) { code = c; runtime.Goexit() }
	defer func() { osExit = saved }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	<-done
	return code
}

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

	t.Run("chain load error returns error", func(t *testing.T) {
		dir := t.TempDir()
		// A directory is not a readable chain file.
		err := runVerify(verifyFlags{chain: dir})
		if err == nil {
			t.Error("runVerify() expected error for directory chain path, got nil")
		}
	})

	t.Run("tampered chain calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, _ := buildAndSaveChain(t, dir, 2)

		// Load, tamper, and save the chain.
		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		chain[0].Result.Passed = !chain[0].Result.Passed
		if err := attestation.SaveChain(chainPath, chain); err != nil {
			t.Fatalf("SaveChain() error = %v", err)
		}

		code := withMockExit(func() {
			runVerify(verifyFlags{chain: chainPath}) //nolint
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for tampered chain, got %d", code)
		}
	})

	t.Run("signer mismatch with valid chain calls osExit(1) and marks chain_valid false", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, pubHex := buildAndSaveChain(t, dir, 1)

		// Generate a different key pair and use its hex as the expected signer.
		wrongKP, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		wrongPubHex := hex.EncodeToString([]byte(wrongKP.PublicKey))
		_ = pubHex

		reportPath := filepath.Join(dir, "report.json")
		code := withMockExit(func() {
			runVerify(verifyFlags{ //nolint
				chain:        chainPath,
				verifySigner: wrongPubHex,
				output:       reportPath,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for signer mismatch, got %d", code)
		}

		// The report should show chain_valid=false.
		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		var report verifyReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatalf("unmarshalling report: %v", err)
		}
		if report.ChainValid {
			t.Error("report.ChainValid should be false for signer mismatch")
		}
	})

	t.Run("output write error returns error", func(t *testing.T) {
		dir := t.TempDir()
		chainPath, _ := buildAndSaveChain(t, dir, 1)

		roDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(roDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.Chmod(roDir, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { os.Chmod(roDir, 0o755) }) //nolint

		err := runVerify(verifyFlags{
			chain:  chainPath,
			output: filepath.Join(roDir, "report.json"),
		})
		if err == nil {
			t.Error("runVerify() expected error for unwritable output path, got nil")
		}
	})
}

// TestRunVerifyViaCobraExecute exercises the cobra RunE closure by calling
// rootCmd.Execute(), which is the only path that covers the RunE lambda body.
func TestRunVerifyViaCobraExecute(t *testing.T) {
	dir := t.TempDir()
	chainPath, _ := buildAndSaveChain(t, dir, 2)
	rootCmd.SetArgs([]string{"--chain", chainPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}
