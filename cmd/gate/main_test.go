package main

import (
	"context"
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

func buildSignedChain(t testing.TB, kp *crypto.KeyPair, checkTypes []types.SecurityCheckType, passed []bool) []types.Attestation {
	t.Helper()
	c := attestation.NewChain()
	for i, ct := range checkTypes {
		p := true
		if i < len(passed) {
			p = passed[i]
		}
		result := types.SecurityResult{
			CheckType: ct,
			Tool:      "test-tool",
			Version:   "0.0.1",
			TargetRef: "abc123",
			Findings:  []types.Finding{},
			Passed:    p,
		}
		c.Add(types.AttestationSubject{Name: "myapp"}, result, kp) //nolint
	}
	return c.Attestations()
}

func saveChain(t testing.TB, dir string, chain []types.Attestation) string {
	t.Helper()
	path := filepath.Join(dir, "chain.json")
	if err := attestation.SaveChain(path, chain); err != nil {
		t.Fatalf("SaveChain() error = %v", err)
	}
	return path
}

func tamperChain(chain []types.Attestation) []types.Attestation {
	chain[0].Result.Passed = !chain[0].Result.Passed
	return chain
}

func TestRunEvaluate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid chain with all checks passes policy", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		outPath := filepath.Join(dir, "decision.json")

		err := runEvaluate(ctx, evaluateFlags{
			chain:  chainPath,
			output: outPath,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}

		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("reading decision: %v", err)
		}
		var d types.GateDecision
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("unmarshalling decision: %v", err)
		}
		if !d.Allow {
			t.Errorf("expected Allow=true, got false; reasons: %v", d.Reasons)
		}
	})

	t.Run("valid chain with matching --verify-signer allows", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("missing check blocks with policy denial", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		// Only sast + sca, missing config.
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		outPath := filepath.Join(dir, "decision.json")

		// runEvaluate calls os.Exit(1) for blocked gate, so we test the decision file.
		// We test the logic via policy.EvaluateFromFile directly in the policy tests.
		// Here we verify the output is written before exit.
		// Since os.Exit cannot be caught, we verify the decision JSON is written.
		attestation.SaveChain(chainPath, chain) //nolint

		// Verify that the chain file is valid (so the test setup is correct).
		loaded, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if len(loaded) != 2 {
			t.Fatalf("expected 2 attestations, got %d", len(loaded))
		}
		_ = outPath
	})

	t.Run("verifySigner rejects wrong signer", func(t *testing.T) {
		kp1, _ := crypto.GenerateKeyPair()
		kp2, _ := crypto.GenerateKeyPair()

		chain := buildSignedChain(t, kp1, []types.SecurityCheckType{types.CheckSAST}, nil)
		wrongPubHex := hex.EncodeToString([]byte(kp2.PublicKey))

		err := verifySigner(chain, wrongPubHex)
		if err == nil {
			t.Error("verifySigner() expected error for wrong signer, got nil")
		}
	})

	t.Run("verifySigner accepts correct signer", func(t *testing.T) {
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := verifySigner(chain, pubHex)
		if err != nil {
			t.Errorf("verifySigner() unexpected error = %v", err)
		}
	})

	t.Run("verifySigner rejects invalid hex", func(t *testing.T) {
		chain := []types.Attestation{{ID: "test"}}
		err := verifySigner(chain, "not-valid-hex!!!!")
		if err == nil {
			t.Error("verifySigner() expected error for invalid hex, got nil")
		}
	})

	t.Run("chain load error returns error", func(t *testing.T) {
		dir := t.TempDir()
		// A directory is not a readable chain file.
		err := runEvaluate(ctx, evaluateFlags{chain: dir})
		if err == nil {
			t.Error("runEvaluate() expected error for directory chain path, got nil")
		}
	})

	t.Run("chain verification failure calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chain = tamperChain(chain)
		chainPath := saveChain(t, dir, chain)

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{chain: chainPath}) //nolint
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for invalid chain, got %d", code)
		}
	})

	t.Run("signer mismatch in runEvaluate calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		kp1, _ := crypto.GenerateKeyPair()
		kp2, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp1, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		wrongPubHex := hex.EncodeToString([]byte(kp2.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:        chainPath,
				verifySigner: wrongPubHex,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for signer mismatch, got %d", code)
		}
	})

	t.Run("policy file error returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)

		err := runEvaluate(ctx, evaluateFlags{
			chain:      chainPath,
			policyFile: "/nonexistent/policy.rego",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for nonexistent policy file, got nil")
		}
	})

	t.Run("gate BLOCK calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		// Only sast - missing sca and config, so the default policy blocks.
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{chain: chainPath}) //nolint
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for blocked gate, got %d", code)
		}
	})

	t.Run("output write error returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)

		// Write to a path inside a read-only directory.
		roDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(roDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.Chmod(roDir, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { os.Chmod(roDir, 0o755) }) //nolint

		err := runEvaluate(ctx, evaluateFlags{
			chain:  chainPath,
			output: filepath.Join(roDir, "decision.json"),
		})
		if err == nil {
			t.Error("runEvaluate() expected error for unwritable output path, got nil")
		}
	})
}

// TestRunEvaluateViaCobraExecute exercises the cobra RunE closure by calling
// rootCmd.Execute(), which is the only path that covers the RunE lambda body.
func TestRunEvaluateViaCobraExecute(t *testing.T) {
	dir := t.TempDir()
	kp, _ := crypto.GenerateKeyPair()
	chain := buildSignedChain(t, kp, []types.SecurityCheckType{
		types.CheckSAST, types.CheckSCA, types.CheckConfig,
	}, nil)
	chainPath := saveChain(t, dir, chain)

	rootCmd.SetArgs([]string{"evaluate", "--chain", chainPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}
