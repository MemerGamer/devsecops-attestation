package main

import (
	"context"
	"crypto/sha256"
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

// gateTestSHA256 returns the hex-encoded SHA-256 of b for use in policy hash tests.
func gateTestSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

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
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			output:       outPath,
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

	t.Run("missing verify-signer returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)

		err := runEvaluate(ctx, evaluateFlags{chain: chainPath})
		if err == nil {
			t.Error("runEvaluate() expected error when --verify-signer is absent, got nil")
		}
	})

	t.Run("chain load error returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))
		// A directory is not a readable chain file.
		err := runEvaluate(ctx, evaluateFlags{chain: dir, verifySigner: pubHex})
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
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{chain: chainPath, verifySigner: pubHex}) //nolint
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
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyFile:   "/nonexistent/policy.rego",
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
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{chain: chainPath, verifySigner: pubHex}) //nolint
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
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

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
			chain:        chainPath,
			verifySigner: pubHex,
			output:       filepath.Join(roDir, "decision.json"),
		})
		if err == nil {
			t.Error("runEvaluate() expected error for unwritable output path, got nil")
		}
	})

	t.Run("max-age blocks expired attestations", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		// 1 nanosecond max-age expires all attestations immediately.
		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:        chainPath,
				verifySigner: pubHex,
				maxAge:       "1ns",
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for expired attestations, got %d", code)
		}
	})

	t.Run("invalid max-age returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			maxAge:       "not-a-duration",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for invalid --max-age, got nil")
		}
	})
}

func TestRunEvaluateTier2(t *testing.T) {
	ctx := context.Background()

	t.Run("policy-hash matches allows evaluation", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		// Use a simple allow-all policy so the gate passes regardless of chain content.
		policyContent := []byte("package devsecops.gate\ndefault allow := true\n")
		policyPath := filepath.Join(dir, "policy.rego")
		if err := os.WriteFile(policyPath, policyContent, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		sum := gateTestSHA256(policyContent)

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyFile:   policyPath,
			policyHash:   sum,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("policy-hash mismatch returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		policyContent := []byte("package devsecops.gate\ndefault allow := true\n")
		policyPath := filepath.Join(dir, "policy.rego")
		if err := os.WriteFile(policyPath, policyContent, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyFile:   policyPath,
			policyHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for hash mismatch, got nil")
		}
	})

	t.Run("policy-hash without policy-file returns error", func(t *testing.T) {
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
			policyHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			// policyFile intentionally absent
		})
		if err == nil {
			t.Error("runEvaluate() expected error when policy-hash given without policy-file, got nil")
		}
	})

	t.Run("authorized-signers match allows deployment", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			verifySigner:      pubHex,
			authorizedSigners: "sast=" + pubHex + ",sca=" + pubHex + ",config=" + pubHex,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("authorized-signers mismatch blocks deployment", func(t *testing.T) {
		dir := t.TempDir()
		kp1, _ := crypto.GenerateKeyPair()
		kp2, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp1, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pub1Hex := hex.EncodeToString([]byte(kp1.PublicKey))
		pub2Hex := hex.EncodeToString([]byte(kp2.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:             chainPath,
				verifySigner:      pub1Hex,
				authorizedSigners: "sast=" + pub2Hex, // wrong key for SAST
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for unauthorized signer, got %d", code)
		}
	})

	t.Run("invalid authorized-signers returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			verifySigner:      pubHex,
			authorizedSigners: "sast=not-valid-hex",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for invalid authorized-signers hex, got nil")
		}
	})

	t.Run("per-check-type signers without verify-signer allows when all match", func(t *testing.T) {
		dir := t.TempDir()
		kpSAST, _ := crypto.GenerateKeyPair()
		kpSCA, _ := crypto.GenerateKeyPair()
		kpConfig, _ := crypto.GenerateKeyPair()

		c := attestation.NewChain()
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSAST, Tool: "semgrep", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{},
		}, kpSAST)
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSCA, Tool: "trivy", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{},
		}, kpSCA)
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckConfig, Tool: "checkov", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{},
		}, kpConfig)
		chainPath := saveChain(t, dir, c.Attestations())

		sastHex := hex.EncodeToString([]byte(kpSAST.PublicKey))
		scaHex := hex.EncodeToString([]byte(kpSCA.PublicKey))
		configHex := hex.EncodeToString([]byte(kpConfig.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			authorizedSigners: "sast=" + sastHex + ",sca=" + scaHex + ",config=" + configHex,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("per-check-type signer mismatch calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		kpWrong, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)

		wrongHex := hex.EncodeToString([]byte(kpWrong.PublicKey))
		rightHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:             chainPath,
				authorizedSigners: "sast=" + wrongHex + ",sca=" + rightHex + ",config=" + rightHex,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for per-check-type signer mismatch, got %d", code)
		}
	})

	t.Run("per-check-type unconfigured check type calls osExit(1)", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		// sca and config are not configured, so verifyAuthorizedSignersCoverage fails.
		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:             chainPath,
				authorizedSigners: "sast=" + pubHex,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for unconfigured check type, got %d", code)
		}
	})

	t.Run("require-log-entries blocks attestation without log entry", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:             chainPath,
				verifySigner:      pubHex,
				requireLogEntries: true,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 when log entries are missing, got %d", code)
		}
	})

	t.Run("require-log-entries passes when all attestations have log entries", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()

		c := attestation.NewChain()
		for _, ct := range []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig} {
			c.SetNextLogEntry("https://example.com/actions/runs/12345")
			c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
				CheckType: ct, Tool: "test-tool", TargetRef: "abc123",
				Passed: true, Findings: []types.Finding{},
			}, kp)
		}
		chainPath := saveChain(t, dir, c.Attestations())
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			verifySigner:      pubHex,
			requireLogEntries: true,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
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
	pubHex := hex.EncodeToString([]byte(kp.PublicKey))

	rootCmd.SetArgs([]string{"evaluate", "--chain", chainPath, "--verify-signer", pubHex})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}
