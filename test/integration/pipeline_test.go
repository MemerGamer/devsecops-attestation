//go:build integration

// Package integration contains end-to-end tests for the full attestation pipeline.
// Run with: go test -tags integration ./test/integration/...
// Run with race detector: go test -tags integration -race ./test/integration/...
package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// binDir holds the directory where TestMain places the compiled binaries.
var binDir string

// TestMain builds all CLI binaries once before running integration tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "devsecops-integration-bin-")
	if err != nil {
		panic("creating temp bin dir: " + err.Error())
	}
	defer os.RemoveAll(dir)
	binDir = dir

	// Build each binary.
	binaries := []struct {
		pkg string
		out string
	}{
		{"./cmd/keygen", "keygen"},
		{"./cmd/sign", "attest"},
		{"./cmd/verify", "verify"},
		{"./cmd/gate", "gate"},
	}

	// Find the module root (two levels up from this file's directory).
	_, thisFile, _, _ := runtime.Caller(0)
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	for _, b := range binaries {
		out := filepath.Join(dir, b.out)
		cmd := exec.Command("go", "build", "-o", out, b.pkg)
		cmd.Dir = moduleRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			panic("building " + b.pkg + ": " + err.Error() + "\n" + string(out))
		}
	}

	os.Exit(m.Run())
}

// --- helpers ---

func bin(name string) string {
	return filepath.Join(binDir, name)
}

func buildChain(t *testing.T, kp *crypto.KeyPair, results []struct {
	checkType types.SecurityCheckType
	passed    bool
	findings  []types.Finding
}) []types.Attestation {
	t.Helper()
	c := attestation.NewChain()
	subject := types.AttestationSubject{Name: "myapp", Digest: "sha256:abc123"}
	for _, r := range results {
		if r.findings == nil {
			r.findings = []types.Finding{}
		}
		result := types.SecurityResult{
			CheckType: r.checkType,
			Tool:      "test-tool",
			Version:   "1.0.0",
			TargetRef: "abc123",
			RunAt:     time.Now().UTC(),
			Findings:  r.findings,
			Passed:    r.passed,
		}
		if _, err := c.Add(subject, result, kp); err != nil {
			t.Fatalf("chain.Add() error = %v", err)
		}
	}
	return c.Attestations()
}

func buildInput(attestations []types.Attestation) types.PolicyInput {
	subject := types.AttestationSubject{Name: "myapp"}
	if len(attestations) > 0 {
		subject = attestations[0].Subject
	}
	return types.PolicyInput{
		Subject:      subject,
		Attestations: attestations,
		RunAt:        time.Now().UTC(),
	}
}

// --- in-process integration tests ---

func TestFullPipelineAllPass(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, true, nil},
		{types.CheckConfig, true, nil},
	})

	// Save and reload to exercise IO path.
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	if err := attestation.SaveChain(chainPath, chain); err != nil {
		t.Fatalf("SaveChain() error = %v", err)
	}
	loaded, err := attestation.LoadChain(chainPath)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}

	results, err := attestation.VerifyChain(loaded)
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}
	for i, r := range results {
		if !r.SignatureValid {
			t.Errorf("chain[%d]: SignatureValid=false: %v", i, r.Error)
		}
		if !r.ChainValid {
			t.Errorf("chain[%d]: ChainValid=false: %v", i, r.Error)
		}
	}

	decision, err := policy.NewEvaluator("").Evaluate(context.Background(), buildInput(loaded))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Allow {
		t.Errorf("Allow=false, reasons=%v", decision.Reasons)
	}
}

func TestFullPipelineCriticalFinding(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, []types.Finding{
			{ID: "CVE-1", Severity: types.SeverityCritical, Title: "critical injection"},
		}},
		{types.CheckSCA, true, nil},
		{types.CheckConfig, true, nil},
	})

	decision, err := policy.NewEvaluator("").Evaluate(context.Background(), buildInput(chain))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Allow {
		t.Error("Allow=true, want false for critical finding")
	}
	found := false
	for _, r := range decision.Reasons {
		if containsSubstr(r, "critical") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reasons %v do not mention 'critical'", decision.Reasons)
	}
}

func TestFullPipelineMissingCheck(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Only sast + sca, no config.
	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, true, nil},
	})

	decision, err := policy.NewEvaluator("").Evaluate(context.Background(), buildInput(chain))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Allow {
		t.Error("Allow=true, want false for missing config check")
	}
	found := false
	for _, r := range decision.Reasons {
		if containsSubstr(r, "missing") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reasons %v do not mention 'missing'", decision.Reasons)
	}
}

func TestFullPipelineFailedCheck(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, false, nil}, // failed
		{types.CheckConfig, true, nil},
	})

	decision, err := policy.NewEvaluator("").Evaluate(context.Background(), buildInput(chain))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Allow {
		t.Error("Allow=true, want false for failed check")
	}
}

func TestFullPipelineTamperedChainBlocksGate(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, true, nil},
		{types.CheckConfig, true, nil},
	})

	// Tamper with the middle attestation's payload.
	chain[1].Result.Passed = false

	// VerifyChain must detect tampering.
	results, _ := attestation.VerifyChain(chain)
	anyError := false
	for _, r := range results {
		if r.Error != nil {
			anyError = true
			break
		}
	}
	if !anyError {
		t.Error("VerifyChain() did not detect tampering; gate would have proceeded to policy evaluation")
	}

	// Policy evaluation must NOT happen once chain verification fails.
	// We simulate the gate precondition check.
	for _, r := range results {
		if !r.SignatureValid || !r.ChainValid {
			// Gate blocks here - test passes.
			return
		}
	}
	t.Error("gate precondition did not block tampered chain")
}

func TestFullPipelineChainInsertionAttack(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, true, nil},
		{types.CheckConfig, true, nil},
	})

	// Insert a malicious attestation at index 1 without updating subsequent PreviousDigests.
	malicious := chain[0] // reuse structure
	malicious.Result.CheckType = types.CheckSAST
	malicious.Result.Passed = true
	inserted := append([]types.Attestation{chain[0], malicious}, chain[1:]...)

	results, _ := attestation.VerifyChain(inserted)
	anyChainError := false
	for _, r := range results {
		if !r.ChainValid {
			anyChainError = true
			break
		}
	}
	if !anyChainError {
		t.Error("VerifyChain() did not detect chain insertion attack")
	}
}

func TestFullPipelineChainReorderAttack(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	chain := buildChain(t, kp, []struct {
		checkType types.SecurityCheckType
		passed    bool
		findings  []types.Finding
	}{
		{types.CheckSAST, true, nil},
		{types.CheckSCA, true, nil},
		{types.CheckConfig, true, nil},
	})

	// Swap chain[0] and chain[1].
	reordered := make([]types.Attestation, len(chain))
	copy(reordered, chain)
	reordered[0], reordered[1] = chain[1], chain[0]

	results, _ := attestation.VerifyChain(reordered)
	// chain[0] (formerly chain[1]) has a non-empty PreviousDigest - chain invalid.
	if results[0].ChainValid {
		t.Error("VerifyChain() should detect reorder: new chain[0] has non-empty PreviousDigest")
	}
}

// --- CLI end-to-end tests ---

// scanResultInput mirrors the JSON format accepted by cmd/sign --result.
type scanResultInput struct {
	Passed   bool           `json:"passed"`
	Findings []types.Finding `json:"findings"`
}

func writeScanResult(t *testing.T, dir string, name string, passed bool, findings []types.Finding) string {
	t.Helper()
	if findings == nil {
		findings = []types.Finding{}
	}
	data, err := json.Marshal(scanResultInput{Passed: passed, Findings: findings})
	if err != nil {
		t.Fatalf("marshalling scan result: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("writing scan result: %v", err)
	}
	return p
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

func TestCLIBinariesEndToEnd(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(dir, "chain.json")

	// Step 1: keygen.
	cmd := exec.Command(bin("keygen"), "--out", keysDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	privHex, err := os.ReadFile(filepath.Join(keysDir, "private.hex"))
	if err != nil {
		t.Fatalf("reading private.hex: %v", err)
	}
	pubHex, err := os.ReadFile(filepath.Join(keysDir, "public.hex"))
	if err != nil {
		t.Fatalf("reading public.hex: %v", err)
	}

	// Validate key hex lengths: private = 128 hex chars (64 bytes), public = 64 hex chars (32 bytes).
	if len(privHex) != 128 {
		t.Errorf("private.hex length = %d hex chars, want 128", len(privHex))
	}
	if len(pubHex) != 64 {
		t.Errorf("public.hex length = %d hex chars, want 64", len(pubHex))
	}

	// Verify keys can be decoded and are cryptographically consistent.
	privBytes, err := hex.DecodeString(string(privHex))
	if err != nil {
		t.Fatalf("decoding private key: %v", err)
	}
	pubBytes, err := hex.DecodeString(string(pubHex))
	if err != nil {
		t.Fatalf("decoding public key: %v", err)
	}
	kp, err := crypto.KeyPairFromBytes(pubBytes, privBytes)
	if err != nil {
		t.Fatalf("KeyPairFromBytes() error = %v", err)
	}
	_ = kp

	// Step 2: sign sast + sca + config.
	checks := []struct {
		checkType string
		name      string
	}{
		{"sast", "sast-result.json"},
		{"sca", "sca-result.json"},
		{"config", "config-result.json"},
	}
	for _, c := range checks {
		resultPath := writeScanResult(t, dir, c.name, true, nil)
		cmd := exec.Command(bin("attest"),
			"--check-type", c.checkType,
			"--tool", "test-tool",
			"--result", resultPath,
			"--target-ref", "abc123",
			"--subject", "myapp",
			"--signing-key", string(privHex),
			"--chain", chainPath,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign %s failed: %v\n%s", c.checkType, err, out)
		}
	}

	// Step 3: verify chain.
	cmd = exec.Command(bin("verify"),
		"--chain", chainPath,
		"--verify-signer", string(pubHex),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}

	// Step 4: gate evaluate - should allow (exit 0).
	policyPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(policyPath, []byte(policy.DefaultPolicy), 0o644); err != nil {
		t.Fatalf("writing policy file: %v", err)
	}
	cmd = exec.Command(bin("gate"), "evaluate",
		"--chain", chainPath,
		"--verify-signer", string(pubHex),
		"--policy", policyPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gate evaluate failed: %v\n%s", err, out)
	}
}

func TestCLIGateBlocksTamperedChain(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(dir, "chain.json")

	// Generate keys.
	cmd := exec.Command(bin("keygen"), "--out", keysDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}
	privHex, _ := os.ReadFile(filepath.Join(keysDir, "private.hex"))
	pubHex, _ := os.ReadFile(filepath.Join(keysDir, "public.hex"))

	// Sign three checks.
	for _, check := range []string{"sast", "sca", "config"} {
		resultPath := writeScanResult(t, dir, check+".json", true, nil)
		cmd := exec.Command(bin("attest"),
			"--check-type", check,
			"--tool", "test-tool",
			"--result", resultPath,
			"--target-ref", "abc123",
			"--subject", "myapp",
			"--signing-key", string(privHex),
			"--chain", chainPath,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sign %s failed: %v\n%s", check, err, out)
		}
	}

	// Tamper with chain JSON directly: flip "passed": true to "passed": false.
	data, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("reading chain: %v", err)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshalling chain: %v", err)
	}
	// Unmarshal first attestation, flip Passed, re-marshal.
	var first types.Attestation
	if err := json.Unmarshal(raw[0], &first); err != nil {
		t.Fatalf("unmarshalling first attestation: %v", err)
	}
	first.Result.Passed = !first.Result.Passed
	tampered, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshalling tampered: %v", err)
	}
	raw[0] = tampered
	out2, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshalling tampered chain: %v", err)
	}
	if err := os.WriteFile(chainPath, out2, 0o644); err != nil {
		t.Fatalf("writing tampered chain: %v", err)
	}

	// gate evaluate must exit non-zero for tampered chain.
	cmd = exec.Command(bin("gate"), "evaluate",
		"--chain", chainPath,
		"--verify-signer", string(pubHex),
	)
	if err := cmd.Run(); err == nil {
		t.Error("gate evaluate should have exited non-zero for tampered chain")
	}
}
