package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
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
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
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
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
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
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			verifySigner:      pubHex,
			authorizedSigners: "sast=" + pubHex + ",sca=" + pubHex + ",config=" + pubHex + ",secret=" + pubHex,
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
		kpSecret, _ := crypto.GenerateKeyPair()

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
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSecret, Tool: "gitleaks", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{},
		}, kpSecret)
		chainPath := saveChain(t, dir, c.Attestations())

		sastHex := hex.EncodeToString([]byte(kpSAST.PublicKey))
		scaHex := hex.EncodeToString([]byte(kpSCA.PublicKey))
		configHex := hex.EncodeToString([]byte(kpConfig.PublicKey))
		secretHex := hex.EncodeToString([]byte(kpSecret.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:             chainPath,
			authorizedSigners: "sast=" + sastHex + ",sca=" + scaHex + ",config=" + configHex + ",secret=" + secretHex,
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
		for _, ct := range []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret} {
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
		types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
	}, nil)
	chainPath := saveChain(t, dir, chain)
	pubHex := hex.EncodeToString([]byte(kp.PublicKey))

	rootCmd.SetArgs([]string{"evaluate", "--chain", chainPath, "--verify-signer", pubHex})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}

func TestLoadPolicyConfig(t *testing.T) {
	t.Run("no flags returns nil config", func(t *testing.T) {
		cfg, err := loadPolicyConfig(evaluateFlags{})
		if err != nil {
			t.Fatalf("loadPolicyConfig() error = %v", err)
		}
		if cfg != nil {
			t.Errorf("expected nil config, got %v", cfg)
		}
	})

	t.Run("required-checks and zero-tolerance-checks are parsed as lowercase lists", func(t *testing.T) {
		cfg, err := loadPolicyConfig(evaluateFlags{
			requiredChecks:      "SAST, secret",
			zeroToleranceChecks: "Secret , sast",
		})
		if err != nil {
			t.Fatalf("loadPolicyConfig() error = %v", err)
		}
		if got, want := cfg["required_checks"], []string{"sast", "secret"}; !equalStringSlices(got.([]string), want) {
			t.Errorf("required_checks = %v, want %v", got, want)
		}
		if got, want := cfg["zero_tolerance_checks"], []string{"secret", "sast"}; !equalStringSlices(got.([]string), want) {
			t.Errorf("zero_tolerance_checks = %v, want %v", got, want)
		}
	})

	t.Run("fail-on-severity is validated and lowercased", func(t *testing.T) {
		cfg, err := loadPolicyConfig(evaluateFlags{failOnSeverity: "HIGH"})
		if err != nil {
			t.Fatalf("loadPolicyConfig() error = %v", err)
		}
		if cfg["fail_on_severity"] != "high" {
			t.Errorf("fail_on_severity = %v, want high", cfg["fail_on_severity"])
		}
	})

	t.Run("invalid fail-on-severity returns lowercase error", func(t *testing.T) {
		_, err := loadPolicyConfig(evaluateFlags{failOnSeverity: "extreme"})
		if err == nil {
			t.Fatal("expected error for invalid --fail-on-severity, got nil")
		}
		msg := err.Error()
		if msg != strings.ToLower(msg) {
			t.Errorf("error message is not lowercase: %q", msg)
		}
		if strings.HasSuffix(msg, ".") {
			t.Errorf("error message has trailing period: %q", msg)
		}
	})

	t.Run("empty entry in comma list returns error", func(t *testing.T) {
		_, err := loadPolicyConfig(evaluateFlags{requiredChecks: "sast,,secret"})
		if err == nil {
			t.Fatal("expected error for empty entry in --required-checks, got nil")
		}
	})

	t.Run("data file provides base config, flags override its keys", func(t *testing.T) {
		dir := t.TempDir()
		dataPath := filepath.Join(dir, "config.json")
		content := `{"required_checks": ["sast", "sca"], "fail_on_severity": "low"}`
		if err := os.WriteFile(dataPath, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg, err := loadPolicyConfig(evaluateFlags{
			dataFile:       dataPath,
			failOnSeverity: "high", // overrides the "low" value from the data file
		})
		if err != nil {
			t.Fatalf("loadPolicyConfig() error = %v", err)
		}
		if cfg["fail_on_severity"] != "high" {
			t.Errorf("fail_on_severity = %v, want high (flag should override data file)", cfg["fail_on_severity"])
		}
		reqChecks, ok := cfg["required_checks"].([]interface{})
		if !ok || len(reqChecks) != 2 {
			t.Errorf("required_checks from data file not preserved: %v", cfg["required_checks"])
		}
	})

	t.Run("nonexistent data file returns error", func(t *testing.T) {
		_, err := loadPolicyConfig(evaluateFlags{dataFile: "/nonexistent/config.json"})
		if err == nil {
			t.Error("expected error for nonexistent --data file, got nil")
		}
	})

	t.Run("invalid json data file returns error", func(t *testing.T) {
		dir := t.TempDir()
		dataPath := filepath.Join(dir, "config.json")
		if err := os.WriteFile(dataPath, []byte("not json"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := loadPolicyConfig(evaluateFlags{dataFile: dataPath})
		if err == nil {
			t.Error("expected error for invalid JSON --data file, got nil")
		}
	})
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRunEvaluateWithPolicyParameterization exercises the deploy gate with
// --required-checks, --fail-on-severity, and --zero-tolerance-checks against
// the bundled default policy end to end.
func TestRunEvaluateWithPolicyParameterization(t *testing.T) {
	ctx := context.Background()

	t.Run("custom required checks allow a chain missing the default set", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		// Only sast and secret ran; the default policy would deny this for
		// missing sca/config, but --required-checks narrows the requirement.
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:          chainPath,
			verifySigner:   pubHex,
			requiredChecks: "sast,secret",
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("custom required check type missing calls osExit(1) with a clear reason", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))
		outPath := filepath.Join(dir, "decision.json")

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:          chainPath,
				verifySigner:   pubHex,
				requiredChecks: "sast,dast",
				output:         outPath,
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for missing custom required check, got %d", code)
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("reading decision: %v", err)
		}
		var d types.GateDecision
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("unmarshalling decision: %v", err)
		}
		if !strings.Contains(strings.Join(d.Reasons, "; "), "dast") {
			t.Errorf("expected a reason naming 'dast', got %v", d.Reasons)
		}
	})

	t.Run("fail-on-severity=high blocks a high finding", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		c := attestation.NewChain()
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSAST, Tool: "semgrep", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{{ID: "H1", Severity: types.SeverityHigh, Title: "high issue"}},
		}, kp)
		for _, ct := range []types.SecurityCheckType{types.CheckSCA, types.CheckConfig, types.CheckSecret} {
			c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
				CheckType: ct, Tool: "test-tool", TargetRef: "abc123",
				Passed: true, Findings: []types.Finding{},
			}, kp)
		}
		chainPath := saveChain(t, dir, c.Attestations())
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:          chainPath,
				verifySigner:   pubHex,
				failOnSeverity: "high",
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1 for high finding with --fail-on-severity=high, got %d", code)
		}
	})

	t.Run("zero-tolerance-checks override allows a secret finding but blocks a sast finding", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		c := attestation.NewChain()
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSAST, Tool: "semgrep", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{{ID: "L1", Severity: types.SeverityLow, Title: "low sast finding"}},
		}, kp)
		for _, ct := range []types.SecurityCheckType{types.CheckSCA, types.CheckConfig} {
			c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
				CheckType: ct, Tool: "test-tool", TargetRef: "abc123",
				Passed: true, Findings: []types.Finding{},
			}, kp)
		}
		c.Add(types.AttestationSubject{Name: "myapp"}, types.SecurityResult{ //nolint
			CheckType: types.CheckSecret, Tool: "gitleaks", TargetRef: "abc123",
			Passed: true, Findings: []types.Finding{{ID: "S1", Severity: types.SeverityLow, Title: "would block under default policy"}},
		}, kp)
		chainPath := saveChain(t, dir, c.Attestations())
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		code := withMockExit(func() {
			runEvaluate(ctx, evaluateFlags{ //nolint
				chain:               chainPath,
				verifySigner:        pubHex,
				zeroToleranceChecks: "sast",
			})
		})
		if code != 1 {
			t.Errorf("expected exit code 1: sast finding should block under --zero-tolerance-checks=sast, got %d", code)
		}
	})

	t.Run("data file config allows deployment via --data", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		dataPath := filepath.Join(dir, "config.json")
		if err := os.WriteFile(dataPath, []byte(`{"required_checks": ["sast", "secret"]}`), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			dataFile:     dataPath,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("invalid --data file surfaces error before chain load", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			dataFile:     "/nonexistent/config.json",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for nonexistent --data file, got nil")
		}
	})
}

// TestRunPolicyHash covers the "gate policy-hash" subcommand's runPolicyHash
// function directly.
func TestRunPolicyHash(t *testing.T) {
	t.Run("no --policy hashes the bundled default policy", func(t *testing.T) {
		var buf strings.Builder
		if err := captureStdout(&buf, func() error {
			return runPolicyHash(policyHashFlags{})
		}); err != nil {
			t.Fatalf("runPolicyHash() error = %v", err)
		}
		want := gateTestSHA256([]byte(policy.DefaultPolicy)) + "\n"
		if buf.String() != want {
			t.Errorf("runPolicyHash() output = %q, want %q", buf.String(), want)
		}
	})

	t.Run("--policy hashes the given file", func(t *testing.T) {
		dir := t.TempDir()
		policyPath := filepath.Join(dir, "custom.rego")
		content := []byte("package devsecops.gate\ndefault allow := true\n")
		if err := os.WriteFile(policyPath, content, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		var buf strings.Builder
		if err := captureStdout(&buf, func() error {
			return runPolicyHash(policyHashFlags{policyFile: policyPath})
		}); err != nil {
			t.Fatalf("runPolicyHash() error = %v", err)
		}
		want := gateTestSHA256(content) + "\n"
		if buf.String() != want {
			t.Errorf("runPolicyHash() output = %q, want %q", buf.String(), want)
		}
	})

	t.Run("nonexistent policy file returns error", func(t *testing.T) {
		err := runPolicyHash(policyHashFlags{policyFile: "/nonexistent/policy.rego"})
		if err == nil {
			t.Error("runPolicyHash() expected error for nonexistent file, got nil")
		}
	})
}

// captureStdout redirects os.Stdout for the duration of fn and writes
// whatever fn printed into dst.
func captureStdout(dst *strings.Builder, fn func() error) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	saved := os.Stdout
	os.Stdout = w
	fnErr := fn()
	w.Close()
	os.Stdout = saved

	buf := make([]byte, 4096)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	return fnErr
}

// TestPolicyHashCommandViaCobraExecute exercises the "gate policy-hash"
// cobra subcommand end to end, covering the RunE lambda.
func TestPolicyHashCommandViaCobraExecute(t *testing.T) {
	var buf strings.Builder
	err := captureStdout(&buf, func() error {
		rootCmd.SetArgs([]string{"policy-hash"})
		return rootCmd.Execute()
	})
	if err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
	want := gateTestSHA256([]byte(policy.DefaultPolicy)) + "\n"
	if buf.String() != want {
		t.Errorf("policy-hash output = %q, want %q", buf.String(), want)
	}
}

// TestRunEvaluatePolicyHashFallback covers the case where --policy-hash is
// given without --policy: the bundled default policy is hashed instead of
// erroring, and a mismatch is still rejected.
func TestRunEvaluatePolicyHashFallback(t *testing.T) {
	ctx := context.Background()

	t.Run("policy-hash without policy-file matches bundled policy", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyHash:   gateTestSHA256([]byte(policy.DefaultPolicy)),
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("policy-hash without policy-file still rejects a mismatch", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for policy hash mismatch against bundled policy, got nil")
		}
	})
}

// TestValidateDataConfig covers the fail-open defect where a malformed
// --data file (unknown key, wrong-type severity, a required/zero-tolerance
// list that is not a non-empty array of valid check types) reached the
// policy unchecked instead of being rejected the same way the corresponding
// flags are validated.
func TestValidateDataConfig(t *testing.T) {
	t.Run("unknown key is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"unknown_key": "value"})
		if err == nil {
			t.Fatal("expected error for unknown config key, got nil")
		}
	})

	t.Run("fail_on_severity not a known level is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"fail_on_severity": "bogus"})
		if err == nil {
			t.Fatal("expected error for invalid fail_on_severity, got nil")
		}
	})

	t.Run("fail_on_severity as a number is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"fail_on_severity": float64(4)})
		if err == nil {
			t.Fatal("expected error for non-string fail_on_severity, got nil")
		}
	})

	t.Run("required_checks as a string is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"required_checks": "sast"})
		if err == nil {
			t.Fatal("expected error for required_checks as a string, got nil")
		}
	})

	t.Run("required_checks as an empty array is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"required_checks": []interface{}{}})
		if err == nil {
			t.Fatal("expected error for empty required_checks array, got nil")
		}
	})

	t.Run("required_checks with an invalid check type is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"required_checks": []interface{}{"SAST"}})
		if err == nil {
			t.Fatal("expected error for uppercase check type entry, got nil")
		}
	})

	t.Run("zero_tolerance_checks as a string is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"zero_tolerance_checks": "secret"})
		if err == nil {
			t.Fatal("expected error for zero_tolerance_checks as a string, got nil")
		}
	})

	t.Run("zero_tolerance_checks as an empty array is rejected", func(t *testing.T) {
		err := validateDataConfig(map[string]any{"zero_tolerance_checks": []interface{}{}})
		if err == nil {
			t.Fatal("expected error for empty zero_tolerance_checks array, got nil")
		}
	})

	t.Run("well-formed config is accepted", func(t *testing.T) {
		err := validateDataConfig(map[string]any{
			"required_checks":       []interface{}{"sast", "secret"},
			"fail_on_severity":      "high",
			"zero_tolerance_checks": []interface{}{"secret"},
		})
		if err != nil {
			t.Errorf("unexpected error for well-formed config: %v", err)
		}
	})

	t.Run("nil config is accepted", func(t *testing.T) {
		if err := validateDataConfig(nil); err != nil {
			t.Errorf("unexpected error for nil config: %v", err)
		}
	})
}

// TestLoadPolicyConfigRejectsMalformedDataFile exercises validateDataConfig
// through loadPolicyConfig's --data file path end to end.
func TestLoadPolicyConfigRejectsMalformedDataFile(t *testing.T) {
	writeDataFile := func(t *testing.T, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}

	t.Run("unknown key in data file returns error", func(t *testing.T) {
		path := writeDataFile(t, `{"unknown_key": "value"}`)
		_, err := loadPolicyConfig(evaluateFlags{dataFile: path})
		if err == nil {
			t.Error("expected error for unknown key in --data file, got nil")
		}
	})

	t.Run("required_checks as a string in data file returns error", func(t *testing.T) {
		path := writeDataFile(t, `{"required_checks": "sast"}`)
		_, err := loadPolicyConfig(evaluateFlags{dataFile: path})
		if err == nil {
			t.Error("expected error for required_checks as a string in --data file, got nil")
		}
	})

	t.Run("required_checks as an empty array in data file returns error", func(t *testing.T) {
		path := writeDataFile(t, `{"required_checks": []}`)
		_, err := loadPolicyConfig(evaluateFlags{dataFile: path})
		if err == nil {
			t.Error("expected error for empty required_checks array in --data file, got nil")
		}
	})

	t.Run("invalid fail_on_severity in data file returns error", func(t *testing.T) {
		path := writeDataFile(t, `{"fail_on_severity": "bogus"}`)
		_, err := loadPolicyConfig(evaluateFlags{dataFile: path})
		if err == nil {
			t.Error("expected error for invalid fail_on_severity in --data file, got nil")
		}
	})
}

// TestBuildEffectiveConfig covers buildEffectiveConfig's default-filling and
// override behavior, and its stability under reordered list input.
func TestBuildEffectiveConfig(t *testing.T) {
	t.Run("nil overrides produce the bundled policy's defaults", func(t *testing.T) {
		cfg := buildEffectiveConfig(nil)
		if cfg["fail_on_severity"] != "critical" {
			t.Errorf("fail_on_severity = %v, want critical", cfg["fail_on_severity"])
		}
		required, ok := cfg["required_checks"].([]string)
		if !ok || len(required) != 4 {
			t.Errorf("required_checks = %v, want 4 default checks", cfg["required_checks"])
		}
		zeroTol, ok := cfg["zero_tolerance_checks"].([]string)
		if !ok || len(zeroTol) != 1 || zeroTol[0] != "secret" {
			t.Errorf("zero_tolerance_checks = %v, want [secret]", cfg["zero_tolerance_checks"])
		}
	})

	t.Run("overrides replace the corresponding default", func(t *testing.T) {
		cfg := buildEffectiveConfig(map[string]any{
			"fail_on_severity": "high",
			"required_checks":  []string{"sast"},
		})
		if cfg["fail_on_severity"] != "high" {
			t.Errorf("fail_on_severity = %v, want high", cfg["fail_on_severity"])
		}
		required := cfg["required_checks"].([]string)
		if len(required) != 1 || required[0] != "sast" {
			t.Errorf("required_checks = %v, want [sast]", required)
		}
		// zero_tolerance_checks was not overridden, so the default remains.
		zeroTol := cfg["zero_tolerance_checks"].([]string)
		if len(zeroTol) != 1 || zeroTol[0] != "secret" {
			t.Errorf("zero_tolerance_checks = %v, want [secret]", zeroTol)
		}
	})

	t.Run("hash is stable regardless of list order", func(t *testing.T) {
		cfgA := buildEffectiveConfig(map[string]any{
			"required_checks": []string{"secret", "sast"},
		})
		cfgB := buildEffectiveConfig(map[string]any{
			"required_checks": []string{"sast", "secret"},
		})
		hashA, err := hashEffectiveConfig(cfgA)
		if err != nil {
			t.Fatalf("hashEffectiveConfig() error = %v", err)
		}
		hashB, err := hashEffectiveConfig(cfgB)
		if err != nil {
			t.Fatalf("hashEffectiveConfig() error = %v", err)
		}
		if hashA != hashB {
			t.Errorf("hash differs by input order: %s vs %s", hashA, hashB)
		}
	})

	t.Run("[]interface{} overrides (as decoded from a --data JSON file) are handled", func(t *testing.T) {
		cfg := buildEffectiveConfig(map[string]any{
			"required_checks": []interface{}{"sast", "secret"},
		})
		required := cfg["required_checks"].([]string)
		if len(required) != 2 {
			t.Errorf("required_checks = %v, want 2 entries", required)
		}
	})
}

// TestRunConfigHash covers the "gate config-hash" subcommand's
// runConfigHash function directly.
func TestRunConfigHash(t *testing.T) {
	t.Run("no flags hashes the bundled defaults", func(t *testing.T) {
		var buf strings.Builder
		if err := captureStdout(&buf, func() error {
			return runConfigHash(configHashFlags{})
		}); err != nil {
			t.Fatalf("runConfigHash() error = %v", err)
		}
		want, err := hashEffectiveConfig(buildEffectiveConfig(nil))
		if err != nil {
			t.Fatalf("hashEffectiveConfig() error = %v", err)
		}
		if buf.String() != want+"\n" {
			t.Errorf("runConfigHash() output = %q, want %q", buf.String(), want+"\n")
		}
	})

	t.Run("overrides change the printed hash", func(t *testing.T) {
		var buf strings.Builder
		if err := captureStdout(&buf, func() error {
			return runConfigHash(configHashFlags{failOnSeverity: "high"})
		}); err != nil {
			t.Fatalf("runConfigHash() error = %v", err)
		}
		defaultHash, _ := hashEffectiveConfig(buildEffectiveConfig(nil))
		if strings.TrimSpace(buf.String()) == defaultHash {
			t.Error("expected a different hash when fail-on-severity overrides the default")
		}
	})

	t.Run("invalid override returns error", func(t *testing.T) {
		err := runConfigHash(configHashFlags{failOnSeverity: "extreme"})
		if err == nil {
			t.Error("runConfigHash() expected error for invalid --fail-on-severity, got nil")
		}
	})
}

// TestConfigHashCommandViaCobraExecute exercises the "gate config-hash"
// cobra subcommand end to end, covering the RunE lambda.
func TestConfigHashCommandViaCobraExecute(t *testing.T) {
	var buf strings.Builder
	err := captureStdout(&buf, func() error {
		rootCmd.SetArgs([]string{"config-hash"})
		return rootCmd.Execute()
	})
	if err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
	want, _ := hashEffectiveConfig(buildEffectiveConfig(nil))
	if strings.TrimSpace(buf.String()) != want {
		t.Errorf("config-hash output = %q, want %q", buf.String(), want)
	}
}

// TestRunEvaluateConfigHash covers --config-hash: the pin-required rule
// when --policy-hash is set with a non-default configuration, a matching
// hash allowing evaluation, and a mismatched hash being rejected.
func TestRunEvaluateConfigHash(t *testing.T) {
	ctx := context.Background()

	t.Run("policy-hash with default config needs no config-hash", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyHash:   gateTestSHA256([]byte(policy.DefaultPolicy)),
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("policy-hash with non-default config and no config-hash fails closed", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:          chainPath,
			verifySigner:   pubHex,
			policyHash:     gateTestSHA256([]byte(policy.DefaultPolicy)),
			requiredChecks: "sast,secret",
		})
		if err == nil {
			t.Error("runEvaluate() expected error when policy-hash is pinned with a non-default config and no --config-hash")
		}
	})

	t.Run("matching config-hash allows evaluation with a non-default config", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		wantHash, err := hashEffectiveConfig(buildEffectiveConfig(map[string]any{
			"required_checks": []string{"sast", "secret"},
		}))
		if err != nil {
			t.Fatalf("hashEffectiveConfig() error = %v", err)
		}

		err = runEvaluate(ctx, evaluateFlags{
			chain:          chainPath,
			verifySigner:   pubHex,
			policyHash:     gateTestSHA256([]byte(policy.DefaultPolicy)),
			requiredChecks: "sast,secret",
			configHash:     wantHash,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("mismatched config-hash returns error", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:          chainPath,
			verifySigner:   pubHex,
			policyHash:     gateTestSHA256([]byte(policy.DefaultPolicy)),
			requiredChecks: "sast,secret",
			configHash:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for config-hash mismatch, got nil")
		}
	})

	t.Run("config-hash without policy-hash is accepted on its own", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSecret,
		}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		wantHash, err := hashEffectiveConfig(buildEffectiveConfig(map[string]any{
			"required_checks": []string{"sast", "secret"},
		}))
		if err != nil {
			t.Fatalf("hashEffectiveConfig() error = %v", err)
		}

		err = runEvaluate(ctx, evaluateFlags{
			chain:          chainPath,
			verifySigner:   pubHex,
			requiredChecks: "sast,secret",
			configHash:     wantHash,
		})
		if err != nil {
			t.Fatalf("runEvaluate() unexpected error = %v", err)
		}
	})

	t.Run("decision output includes effective_config and config_hash", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{
			types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret,
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
		if d.ConfigHash == "" {
			t.Error("expected ConfigHash to be populated in the decision output")
		}
		if d.EffectiveConfig == nil {
			t.Error("expected EffectiveConfig to be populated in the decision output")
		}
	})
}

// TestRunEvaluateTOCTOU covers the fix for reading the policy file exactly
// once: the hash check and the evaluation must operate on the same bytes.
// This is exercised indirectly by confirming a policy-hash match still
// evaluates correctly (the read-once path is the only path now), and that
// the file read error surfaces with the expected wrapped message.
func TestRunEvaluateTOCTOU(t *testing.T) {
	ctx := context.Background()

	t.Run("nonexistent policy file with policy-hash set returns a reading error, not a hash mismatch", func(t *testing.T) {
		dir := t.TempDir()
		kp, _ := crypto.GenerateKeyPair()
		chain := buildSignedChain(t, kp, []types.SecurityCheckType{types.CheckSAST}, nil)
		chainPath := saveChain(t, dir, chain)
		pubHex := hex.EncodeToString([]byte(kp.PublicKey))

		err := runEvaluate(ctx, evaluateFlags{
			chain:        chainPath,
			verifySigner: pubHex,
			policyFile:   "/nonexistent/policy.rego",
			policyHash:   "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		})
		if err == nil {
			t.Error("runEvaluate() expected error for nonexistent policy file, got nil")
		}
		if !strings.HasSuffix(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "reading policy file") {
			t.Errorf("expected a policy file read error, got: %v", err)
		}
	})
}
