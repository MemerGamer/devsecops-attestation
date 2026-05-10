package policy_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// buildAttestation creates a minimal signed-enough attestation for policy tests.
// Policy evaluation does not re-verify signatures, so we leave them empty.
func buildAttestation(checkType types.SecurityCheckType, passed bool, findings []types.Finding) types.Attestation {
	if findings == nil {
		findings = []types.Finding{}
	}
	return types.Attestation{
		ID: "test-" + string(checkType),
		Subject: types.AttestationSubject{
			Name:   "myapp",
			Digest: "sha256:abc",
		},
		Result: types.SecurityResult{
			CheckType: checkType,
			Tool:      "test-tool",
			Version:   "0.0.1",
			TargetRef: "abc123",
			RunAt:     time.Now().UTC(),
			Findings:  findings,
			Passed:    passed,
		},
		Timestamp: time.Now().UTC(),
	}
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

func sortedReasons(reasons []string) []string {
	out := make([]string, len(reasons))
	copy(out, reasons)
	sort.Strings(out)
	return out
}

func containsReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func TestDefaultPolicyRego(t *testing.T) {
	ctx := context.Background()

	// Verify the DefaultPolicy string compiles without error.
	e := policy.NewEvaluator("")
	input := buildInput([]types.Attestation{
		buildAttestation(types.CheckSAST, true, nil),
		buildAttestation(types.CheckSCA, true, nil),
		buildAttestation(types.CheckConfig, true, nil),
	})
	if _, err := e.Evaluate(ctx, input); err != nil {
		t.Errorf("DefaultPolicy failed to compile or evaluate: %v", err)
	}
}

func TestEvaluate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		attestations []types.Attestation
		wantAllow    bool
		wantReasons  []string // substrings that must appear in reasons
	}{
		// Allow cases
		{
			name: "all three required checks passed, no findings",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, nil),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   true,
			wantReasons: []string{"all checks passed"},
		},
		{
			name: "four checks including optional secret scan",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, nil),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
				buildAttestation(types.CheckSecret, true, nil),
			},
			wantAllow:   true,
			wantReasons: []string{"all checks passed"},
		},
		{
			name: "medium findings only do not block",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "M1", Severity: types.SeverityMedium, Title: "medium issue"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   true,
			wantReasons: []string{"all checks passed"},
		},
		{
			name: "high severity findings do not block (policy only blocks critical)",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "H1", Severity: types.SeverityHigh, Title: "high issue"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   true,
			wantReasons: []string{"all checks passed"},
		},

		// Deny cases
		{
			name: "missing sast check",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   false,
			wantReasons: []string{"missing required checks"},
		},
		{
			name:         "empty attestation list",
			attestations: []types.Attestation{},
			wantAllow:    false,
			wantReasons:  []string{"missing required checks"},
		},
		{
			name: "critical finding present",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "C1", Severity: types.SeverityCritical, Title: "critical injection"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   false,
			wantReasons: []string{"critical finding"},
		},
		{
			name: "failed check blocks deployment",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, nil),
				buildAttestation(types.CheckSCA, false, nil),
				buildAttestation(types.CheckConfig, true, nil),
			},
			wantAllow:   false,
			wantReasons: []string{"failed checks"},
		},
		{
			name: "critical finding and missing check produce both reasons",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "C1", Severity: types.SeverityCritical, Title: "critical issue"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				// config is missing
			},
			wantAllow:   false,
			wantReasons: []string{"critical finding", "missing required checks"},
		},
		{
			name: "only sast passed, sca and config missing",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, nil),
			},
			wantAllow:   false,
			wantReasons: []string{"missing required checks"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := policy.NewEvaluator("")
			input := buildInput(tt.attestations)

			decision, err := e.Evaluate(ctx, input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if decision.Allow != tt.wantAllow {
				t.Errorf("Allow = %v, want %v; reasons = %v", decision.Allow, tt.wantAllow, decision.Reasons)
			}

			for _, want := range tt.wantReasons {
				if !containsReason(decision.Reasons, want) {
					t.Errorf("reasons %v do not contain expected substring %q", sortedReasons(decision.Reasons), want)
				}
			}
		})
	}
}

func TestEvaluateEdgeCases(t *testing.T) {
	ctx := context.Background()
	input := buildInput([]types.Attestation{})

	t.Run("empty policy returns allow=false when no allow rule defined", func(t *testing.T) {
		// The empty policy defines no allow rule so allowRS is empty,
		// covering the len(allowRS)==0 branch (line 130).
		policyPath := filepath.Join("testdata", "empty.rego")
		decision, err := policy.EvaluateFromFile(ctx, policyPath, input)
		if err != nil {
			t.Fatalf("EvaluateFromFile() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for empty policy, got true")
		}
	})

	t.Run("deny_reasons as non-map scalar is handled without panic", func(t *testing.T) {
		// This policy returns deny_reasons as a string (not a set/map), covering
		// the ok=false branch of the type assertion on line 141.
		policyPath := filepath.Join("testdata", "deny-reasons-string.rego")
		decision, err := policy.EvaluateFromFile(ctx, policyPath, input)
		if err != nil {
			t.Fatalf("EvaluateFromFile() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for deny policy, got true")
		}
		// No reasons should be collected when deny_reasons is not a map/set.
		if len(decision.Reasons) != 0 {
			t.Errorf("expected no reasons for non-map deny_reasons, got %v", decision.Reasons)
		}
	})

	t.Run("invalid Rego syntax returns eval error", func(t *testing.T) {
		// A syntactically invalid policy causes allowQuery.Eval to return an error,
		// covering lines 126-128.
		e := policy.NewEvaluator("this is not valid rego }{")
		_, err := e.Evaluate(ctx, input)
		if err == nil {
			t.Error("Evaluate() expected error for invalid Rego, got nil")
		}
	})
}

func TestEvaluateFromFile(t *testing.T) {
	ctx := context.Background()

	allChecks := []types.Attestation{
		buildAttestation(types.CheckSAST, true, nil),
		buildAttestation(types.CheckSCA, true, nil),
		buildAttestation(types.CheckConfig, true, nil),
	}
	input := buildInput(allChecks)

	t.Run("empty path uses DefaultPolicy", func(t *testing.T) {
		decision, err := policy.EvaluateFromFile(ctx, "", input)
		if err != nil {
			t.Fatalf("EvaluateFromFile() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true, got false; reasons = %v", decision.Reasons)
		}
	})

	t.Run("deny-all policy file blocks all deployments", func(t *testing.T) {
		policyPath := filepath.Join("testdata", "deny-all.rego")
		decision, err := policy.EvaluateFromFile(ctx, policyPath, input)
		if err != nil {
			t.Fatalf("EvaluateFromFile() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for deny-all policy, got true")
		}
	})

	t.Run("permissive policy file allows all deployments", func(t *testing.T) {
		policyPath := filepath.Join("testdata", "permissive.rego")
		// Even an empty input would pass with permissive policy.
		emptyInput := buildInput([]types.Attestation{})
		decision, err := policy.EvaluateFromFile(ctx, policyPath, emptyInput)
		if err != nil {
			t.Fatalf("EvaluateFromFile() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true for permissive policy, got false; reasons = %v", decision.Reasons)
		}
	})

	t.Run("written policy file same as DefaultPolicy produces same result", func(t *testing.T) {
		dir := t.TempDir()
		policyPath := filepath.Join(dir, "policy.rego")
		if err := os.WriteFile(policyPath, []byte(policy.DefaultPolicy), 0o644); err != nil {
			t.Fatalf("writing policy file: %v", err)
		}

		directDecision, err := policy.EvaluateFromFile(ctx, "", input)
		if err != nil {
			t.Fatalf("direct EvaluateFromFile() error = %v", err)
		}
		fileDecision, err := policy.EvaluateFromFile(ctx, policyPath, input)
		if err != nil {
			t.Fatalf("file EvaluateFromFile() error = %v", err)
		}

		if directDecision.Allow != fileDecision.Allow {
			t.Errorf("Allow mismatch: direct=%v, file=%v", directDecision.Allow, fileDecision.Allow)
		}
	})

	t.Run("nonexistent policy file returns error", func(t *testing.T) {
		_, err := policy.EvaluateFromFile(ctx, "/nonexistent/policy.rego", input)
		if err == nil {
			t.Error("expected error for nonexistent policy file, got nil")
		}
	})
}

// buildSignedAttestation creates a signed attestation for policy tests that need
// a real SignerPublicKey so that authorized_signers checks have something to compare.
func buildSignedAttestation(t *testing.T, checkType types.SecurityCheckType, passed bool, findings []types.Finding, kp *crypto.KeyPair) types.Attestation {
	t.Helper()
	a := buildAttestation(checkType, passed, findings)
	if err := crypto.Sign(&a, kp); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return a
}

func TestAuthorizedSigners(t *testing.T) {
	ctx := context.Background()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	pubHex := hex.EncodeToString([]byte(kp.PublicKey))

	kpOther, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() other error = %v", err)
	}
	otherPubHex := hex.EncodeToString([]byte(kpOther.PublicKey))

	t.Run("matching authorized signers allow deployment", func(t *testing.T) {
		attestations := []types.Attestation{
			buildSignedAttestation(t, types.CheckSAST, true, nil, kp),
			buildSignedAttestation(t, types.CheckSCA, true, nil, kp),
			buildSignedAttestation(t, types.CheckConfig, true, nil, kp),
		}
		input := types.PolicyInput{
			Subject:      attestations[0].Subject,
			Attestations: attestations,
			AuthorizedSigners: map[string]string{
				"sast":   pubHex,
				"sca":    pubHex,
				"config": pubHex,
			},
		}

		decision, err := policy.NewEvaluator("").Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("Allow=false with matching authorized signers; reasons=%v", decision.Reasons)
		}
	})

	t.Run("mismatched authorized signer blocks deployment", func(t *testing.T) {
		attestations := []types.Attestation{
			buildSignedAttestation(t, types.CheckSAST, true, nil, kp),
			buildSignedAttestation(t, types.CheckSCA, true, nil, kp),
			buildSignedAttestation(t, types.CheckConfig, true, nil, kp),
		}
		input := types.PolicyInput{
			Subject:      attestations[0].Subject,
			Attestations: attestations,
			AuthorizedSigners: map[string]string{
				"sast": otherPubHex, // wrong key
			},
		}

		decision, err := policy.NewEvaluator("").Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("Allow=true despite mismatched authorized signer")
		}
		if !containsReason(decision.Reasons, "unauthorized signer") {
			t.Errorf("reasons %v should mention 'unauthorized signer'", decision.Reasons)
		}
	})

	t.Run("no authorized_signers configured passes all signers", func(t *testing.T) {
		attestations := []types.Attestation{
			buildSignedAttestation(t, types.CheckSAST, true, nil, kp),
			buildSignedAttestation(t, types.CheckSCA, true, nil, kp),
			buildSignedAttestation(t, types.CheckConfig, true, nil, kp),
		}
		input := types.PolicyInput{
			Subject:      attestations[0].Subject,
			Attestations: attestations,
			// AuthorizedSigners intentionally empty
		}

		decision, err := policy.NewEvaluator("").Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("Allow=false without authorized_signers configured; reasons=%v", decision.Reasons)
		}
	})

	t.Run("partial authorized_signers only checks configured types", func(t *testing.T) {
		// Only SAST signer is constrained; SCA and Config can use any key.
		attestations := []types.Attestation{
			buildSignedAttestation(t, types.CheckSAST, true, nil, kp),
			buildSignedAttestation(t, types.CheckSCA, true, nil, kpOther),   // different key, not constrained
			buildSignedAttestation(t, types.CheckConfig, true, nil, kpOther), // different key, not constrained
		}
		input := types.PolicyInput{
			Subject:      attestations[0].Subject,
			Attestations: attestations,
			AuthorizedSigners: map[string]string{
				"sast": pubHex, // only SAST is constrained
			},
		}

		decision, err := policy.NewEvaluator("").Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("Allow=false but only SAST is constrained and matches; reasons=%v", decision.Reasons)
		}
	})
}
