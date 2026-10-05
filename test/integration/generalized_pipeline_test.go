//go:build integration

// Package integration - generalized pipeline test.
// Exercises the full raw-tool-output -> normalize -> sign -> verify -> gate
// flow using the pkg/normalize adapters and the bundled default policy, the
// same library functions cmd/sign, cmd/verify, and cmd/gate call internally.
// Run with: go test -tags integration -run TestGeneralizedPipeline ./test/integration/ -v
package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/normalize"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// normalizeFixture runs the named normalizer adapter over a testdata fixture
// file, the same call cmd/sign's normalize path makes, and returns the
// canonical Result.
func normalizeFixture(t *testing.T, adapter, fixturePath string, failOn normalize.Severity) normalize.Result {
	t.Helper()
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("opening fixture %s: %v", fixturePath, err)
	}
	defer f.Close()

	result, err := normalize.Run(adapter, f, failOn)
	if err != nil {
		t.Fatalf("normalize.Run(%s) error = %v", adapter, err)
	}
	return result
}

// signNormalized signs a normalized Result under the given check type and
// tool name, appending it to chain c with kp, mirroring what cmd/sign does
// after invoking normalize.Run.
func signNormalized(t *testing.T, c *attestation.Chain, subject types.AttestationSubject, checkType types.SecurityCheckType, tool string, result normalize.Result, kp *crypto.KeyPair) *types.Attestation {
	t.Helper()
	sr := types.SecurityResult{
		CheckType:   checkType,
		Tool:        tool,
		Version:     "1.0.0",
		TargetRef:   "abc123",
		PassedCount: result.PassedCount,
		Findings:    result.Findings,
		Passed:      result.Passed,
	}
	a, err := c.Add(subject, sr, kp)
	if err != nil {
		t.Fatalf("chain.Add(%s) error = %v", checkType, err)
	}
	return a
}

// generalizedFixture returns the absolute path to a pkg/normalize testdata
// fixture file.
func generalizedFixture(elem ...string) string {
	base := []string{"..", "..", "pkg", "normalize", "testdata"}
	return filepath.Join(append(base, elem...)...)
}

// authorizedSignersFor builds the hex-encoded authorized signer map used by
// gate's --authorized-signers flag / verifyAuthorizedSignersCoverage.
func authorizedSignersFor(keys map[types.SecurityCheckType]*crypto.KeyPair) map[string]string {
	out := make(map[string]string, len(keys))
	for checkType, kp := range keys {
		out[string(checkType)] = hex.EncodeToString([]byte(kp.PublicKey))
	}
	return out
}

// verifyAuthorizedSignersCoverage replicates cmd/gate's unexported check of
// the same name: every attestation's check type must have a configured
// authorized signer, and the signer must match. It is duplicated here
// because cmd/gate only exposes it from package main.
func verifyAuthorizedSignersCoverage(t *testing.T, chain []types.Attestation, authorized map[string]string) error {
	t.Helper()
	for i, a := range chain {
		checkType := string(a.Result.CheckType)
		expectedHex, ok := authorized[checkType]
		if !ok {
			return fmt.Errorf("attestation %d (%s): no authorized signer configured for check type %q", i, a.ID, checkType)
		}
		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			t.Fatalf("decoding authorized signer hex for check type %q: %v", checkType, err)
		}
		if !bytes.Equal(a.SignerPublicKey, expected) {
			return fmt.Errorf("attestation %d (%s): signer does not match authorized signer for check type %q", i, a.ID, checkType)
		}
	}
	return nil
}

// runGate replicates the verification and evaluation sequence enforced by
// cmd/gate's runEvaluate: VerifyChainWithOptions, then signer authorization,
// then OPA policy evaluation against the bundled default policy (policy
// path "" resolves to policy.DefaultPolicy inside EvaluateFromFile).
func runGate(t *testing.T, chain []types.Attestation, authorized map[string]string, config map[string]any) *types.GateDecision {
	t.Helper()

	if _, err := attestation.VerifyChainWithOptions(chain, attestation.VerifyOptions{}); err != nil {
		t.Fatalf("VerifyChainWithOptions() unexpected error = %v", err)
	}

	if err := verifyAuthorizedSignersCoverage(t, chain, authorized); err != nil {
		t.Fatalf("verifyAuthorizedSignersCoverage() unexpected error = %v", err)
	}

	subject := types.AttestationSubject{}
	if len(chain) > 0 {
		subject = chain[0].Subject
	}
	input := types.PolicyInput{
		Subject:           subject,
		Attestations:      chain,
		AuthorizedSigners: authorized,
	}

	decision, err := policy.EvaluateFromFile(context.Background(), "", input, policy.WithData(config))
	if err != nil {
		t.Fatalf("EvaluateFromFile() error = %v", err)
	}
	return decision
}

// saveAndReloadChain round-trips the chain through disk, exercising the same
// SaveChain/LoadChain path cmd/sign and cmd/gate use.
func saveAndReloadChain(t *testing.T, chain []types.Attestation) []types.Attestation {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	if err := attestation.SaveChain(path, chain); err != nil {
		t.Fatalf("SaveChain() error = %v", err)
	}
	loaded, err := attestation.LoadChain(path)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}
	return loaded
}

// buildGeneralizedChain normalizes the four standard tool fixtures (sast,
// sca, config, secret) and signs them into one chain, each check type with
// its own key pair. gitleaksFixture selects which gitleaks fixture ("clean"
// or "findings") is used for the secret check.
func buildGeneralizedChain(t *testing.T, gitleaksFixture string) ([]types.Attestation, map[string]string) {
	t.Helper()
	subject := types.AttestationSubject{Name: "generalized-app", Digest: "sha256:def456"}

	keys := map[types.SecurityCheckType]*crypto.KeyPair{}
	for _, ct := range []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret} {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		keys[ct] = kp
	}

	c := attestation.NewChain()

	semgrepResult := normalizeFixture(t, "semgrep", generalizedFixture("semgrep", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSAST, "semgrep", semgrepResult, keys[types.CheckSAST])

	trivyResult := normalizeFixture(t, "trivy", generalizedFixture("trivy", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSCA, "trivy", trivyResult, keys[types.CheckSCA])

	checkovResult := normalizeFixture(t, "checkov", generalizedFixture("checkov", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckConfig, "checkov", checkovResult, keys[types.CheckConfig])

	gitleaksResult := normalizeFixture(t, "gitleaks", generalizedFixture("gitleaks", gitleaksFixture+".json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSecret, "gitleaks", gitleaksResult, keys[types.CheckSecret])

	return saveAndReloadChain(t, c.Attestations()), authorizedSignersFor(keys)
}

// TestGeneralizedPipelineAllCleanAllows covers scenario (a): raw fixtures for
// all four standard checks, none with findings, normalized and signed with
// four distinct keys, verified, and evaluated against the bundled default
// policy with per-check-type authorized signers. The chain must be allowed.
func TestGeneralizedPipelineAllCleanAllows(t *testing.T) {
	chain, authorized := buildGeneralizedChain(t, "clean")

	decision := runGate(t, chain, authorized, nil)
	if !decision.Allow {
		t.Errorf("Allow=false, want true; reasons=%v", decision.Reasons)
	}
}

// TestGeneralizedPipelineGitleaksFindingsDenies covers scenario (b): the same
// flow but with the gitleaks fixture that contains findings. Secret is a
// zero-tolerance check type in the default policy, so the chain must be
// denied with the hardcoded-credential reason.
func TestGeneralizedPipelineGitleaksFindingsDenies(t *testing.T) {
	chain, authorized := buildGeneralizedChain(t, "findings")

	decision := runGate(t, chain, authorized, nil)
	if decision.Allow {
		t.Error("Allow=true, want false for chain with gitleaks findings")
	}
	found := false
	for _, r := range decision.Reasons {
		if strings.Contains(r, "hardcoded credential") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reasons %v do not mention hardcoded credential finding(s)", decision.Reasons)
	}
}

// TestGeneralizedPipelineCustomRequiredChecks covers scenario (c): a custom
// data.config.required_checks list naming a non-standard "dast" check type,
// normalized through the generic passthrough adapter. Present, the chain is
// allowed; absent, the chain is denied for missing required checks. Since
// the policy now seals the chain against undeclared check types (any
// attestation whose check_type is not in required_checks is rejected),
// required_checks must name every check type the chain carries, not only
// the one under test - operators adding a custom check type append it to
// the existing list rather than replacing it.
func TestGeneralizedPipelineCustomRequiredChecks(t *testing.T) {
	config := map[string]any{
		"required_checks": []string{"sast", "sca", "config", "secret", "dast"},
	}

	t.Run("dast present is allowed", func(t *testing.T) {
		chain, authorized := buildGeneralizedChain(t, "clean")

		dastKP, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		subject := chain[0].Subject
		c := attestation.NewChainFromSlice(chain)
		dastResult := normalizeFixture(t, "generic", generalizedFixture("generic", "clean.json"), normalize.SeverityCritical)
		signNormalized(t, c, subject, types.SecurityCheckType("dast"), "zap", dastResult, dastKP)
		chain = saveAndReloadChain(t, c.Attestations())
		authorized["dast"] = hex.EncodeToString([]byte(dastKP.PublicKey))

		decision := runGate(t, chain, authorized, config)
		if !decision.Allow {
			t.Errorf("Allow=false, want true with dast present; reasons=%v", decision.Reasons)
		}
	})

	t.Run("dast absent is denied for missing required checks", func(t *testing.T) {
		chain, authorized := buildGeneralizedChain(t, "clean")

		decision := runGate(t, chain, authorized, config)
		if decision.Allow {
			t.Error("Allow=true, want false when dast is absent but required")
		}
		found := false
		for _, r := range decision.Reasons {
			if strings.Contains(r, "missing required checks") && strings.Contains(r, "dast") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("reasons %v do not mention missing dast check", decision.Reasons)
		}
	})
}

// TestGeneralizedPipelineFailOnSeverityHigh covers scenario (d): a chain
// containing a semgrep ERROR (high) finding, which the default policy
// already denies (fail_on_severity defaults to "high"), and which a
// data.config.fail_on_severity of "critical" (raising the threshold) would
// instead allow, since sast is not a zero-tolerance check type.
func TestGeneralizedPipelineFailOnSeverityHigh(t *testing.T) {
	subject := types.AttestationSubject{Name: "generalized-app", Digest: "sha256:def456"}
	keys := map[types.SecurityCheckType]*crypto.KeyPair{}
	for _, ct := range []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig, types.CheckSecret} {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		keys[ct] = kp
	}

	c := attestation.NewChain()

	// semgrep findings.json contains an ERROR-severity finding, which maps to
	// "high" (see docs/severity-mapping.md), and lower-severity findings that
	// do not block at any threshold used here. failOn is set above high so
	// Result.Passed reflects the raw scan outcome, not this test's policy
	// threshold.
	semgrepResult := normalizeFixture(t, "semgrep", generalizedFixture("semgrep", "findings.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSAST, "semgrep", semgrepResult, keys[types.CheckSAST])

	trivyResult := normalizeFixture(t, "trivy", generalizedFixture("trivy", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSCA, "trivy", trivyResult, keys[types.CheckSCA])

	checkovResult := normalizeFixture(t, "checkov", generalizedFixture("checkov", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckConfig, "checkov", checkovResult, keys[types.CheckConfig])

	gitleaksResult := normalizeFixture(t, "gitleaks", generalizedFixture("gitleaks", "clean.json"), normalize.SeverityCritical)
	signNormalized(t, c, subject, types.CheckSecret, "gitleaks", gitleaksResult, keys[types.CheckSecret])

	chain := saveAndReloadChain(t, c.Attestations())
	authorized := authorizedSignersFor(keys)

	// Default policy config: fail_on_severity defaults to "high", so the
	// high-severity semgrep finding blocks deployment.
	baseline := runGate(t, chain, authorized, nil)
	if baseline.Allow {
		t.Errorf("baseline Allow=true, want false (default fail_on_severity=high should block a high finding); reasons=%v", baseline.Reasons)
	}
	found := false
	for _, r := range baseline.Reasons {
		if strings.Contains(r, "high") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reasons %v do not mention the high severity threshold", baseline.Reasons)
	}

	// Raising data.config.fail_on_severity to "critical" must now allow the
	// same chain, since the semgrep finding is only high, not critical.
	lenient := runGate(t, chain, authorized, map[string]any{
		"fail_on_severity": "critical",
	})
	if !lenient.Allow {
		t.Errorf("lenient Allow=false, want true with fail_on_severity=critical and only a high-severity finding present; reasons=%v", lenient.Reasons)
	}
}
