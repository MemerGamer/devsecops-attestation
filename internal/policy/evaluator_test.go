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

// TestBundledPolicyParsesAsRegoV1 asserts that the bundled default policy
// (policies/deploy.rego, embedded as policy.DefaultPolicy) uses rego.v1
// syntax and compiles and evaluates without error.
func TestBundledPolicyParsesAsRegoV1(t *testing.T) {
	if !strings.Contains(policy.DefaultPolicy, "import rego.v1") {
		t.Fatalf("DefaultPolicy does not import rego.v1:\n%s", policy.DefaultPolicy)
	}

	ctx := context.Background()
	e := policy.NewEvaluator(policy.DefaultPolicy)
	input := buildInput([]types.Attestation{
		buildAttestation(types.CheckSAST, true, nil),
		buildAttestation(types.CheckSCA, true, nil),
		buildAttestation(types.CheckConfig, true, nil),
		buildAttestation(types.CheckSecret, true, nil),
	})
	decision, err := e.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Allow {
		t.Errorf("expected Allow=true, got false; reasons=%v", decision.Reasons)
	}
}

func TestPolicyDataParameterization(t *testing.T) {
	ctx := context.Background()

	t.Run("custom required checks: only sast and secret required", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": []string{"sast", "secret"},
		}))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true with only sast+secret required, got false; reasons=%v", decision.Reasons)
		}
	})

	t.Run("custom required check type missing produces clear deny reason", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": []string{"sast", "dast"},
		}))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false when custom required check 'dast' is missing")
		}
		if !containsReason(decision.Reasons, "dast") || !containsReason(decision.Reasons, "missing required checks") {
			t.Errorf("expected a deny reason naming the missing 'dast' check, got %v", decision.Reasons)
		}
	})

	t.Run("fail_on_severity=high blocks a high severity finding", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"fail_on_severity": "high",
		}))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, []types.Finding{
				{ID: "H1", Severity: types.SeverityHigh, Title: "high issue"},
			}),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false: high finding should block when fail_on_severity=high")
		}
		if !containsReason(decision.Reasons, "at or above") {
			t.Errorf("expected a severity-threshold deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("fail_on_severity=high does not block a medium finding", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"fail_on_severity": "high",
		}))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, []types.Finding{
				{ID: "M1", Severity: types.SeverityMedium, Title: "medium issue"},
			}),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true: medium finding should not block when fail_on_severity=high; reasons=%v", decision.Reasons)
		}
	})

	t.Run("zero_tolerance_checks override blocks findings on a non-default check type", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"zero_tolerance_checks": []string{"sast"},
		}))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, []types.Finding{
				{ID: "L1", Severity: types.SeverityLow, Title: "low severity sast finding"},
			}),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			// A secret-scan finding no longer blocks, since zero tolerance was
			// overridden to sast only.
			buildAttestation(types.CheckSecret, true, []types.Finding{
				{ID: "S1", Severity: types.SeverityLow, Title: "would have blocked under default policy"},
			}),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false: sast finding should block under zero_tolerance_checks=[sast]")
		}
		if !containsReason(decision.Reasons, "zero-tolerance") {
			t.Errorf("expected a zero-tolerance deny reason, got %v", decision.Reasons)
		}
		if containsReason(decision.Reasons, "hardcoded credential") {
			t.Errorf("secret-scan finding should not block once zero tolerance no longer covers 'secret'; reasons=%v", decision.Reasons)
		}
	})

	t.Run("nil data leaves policy defaults in effect", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(nil))
		input := buildInput([]types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		})
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true with default config, got false; reasons=%v", decision.Reasons)
		}
	})
}

// TestPolicyFailClosedOnMalformedConfig covers the fail-open defects found in
// review: a malformed data.config value must deny deployment instead of
// silently disabling the check it was meant to configure.
func TestPolicyFailClosedOnMalformedConfig(t *testing.T) {
	ctx := context.Background()

	allChecksNoFindings := func() []types.Attestation {
		return []types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		}
	}

	t.Run("unrecognized fail_on_severity string denies", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"fail_on_severity": "bogus",
		}))
		decision, err := e.Evaluate(ctx, buildInput(allChecksNoFindings()))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for fail_on_severity=\"bogus\"")
		}
		if !containsReason(decision.Reasons, "invalid data.config.fail_on_severity") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("wrong-case fail_on_severity denies", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"fail_on_severity": "CRITICAL",
		}))
		decision, err := e.Evaluate(ctx, buildInput(allChecksNoFindings()))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for fail_on_severity=\"CRITICAL\"")
		}
	})

	t.Run("numeric fail_on_severity denies and still blocks a critical finding", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"fail_on_severity": 4,
		}))
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, true, []types.Finding{
				{ID: "C1", Severity: types.SeverityCritical, Title: "critical issue"},
			}),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false for fail_on_severity=4 with a critical finding present")
		}
		if !containsReason(decision.Reasons, "invalid data.config.fail_on_severity") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
		// blocking_threshold must fall back to the critical rank so the
		// critical finding is still caught, not silently skipped.
		if !containsReason(decision.Reasons, "found 1 finding(s) at or above the critical severity threshold") {
			t.Errorf("expected the critical finding to still be reported, got %v", decision.Reasons)
		}
	})

	t.Run("required_checks as a string denies instead of vacuous allow", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": "sast",
		}))
		decision, err := e.Evaluate(ctx, buildInput(nil))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false when required_checks is a string, not an array")
		}
		if !containsReason(decision.Reasons, "invalid data.config.required_checks") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("required_checks as an empty array denies instead of vacuous allow", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": []string{},
		}))
		decision, err := e.Evaluate(ctx, buildInput(nil))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false when required_checks is an empty array")
		}
		if !containsReason(decision.Reasons, "invalid data.config.required_checks") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("zero_tolerance_checks as a string denies instead of allowing secrets", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"zero_tolerance_checks": "secret",
		}))
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, []types.Finding{
				{ID: "S1", Severity: types.SeverityLow, Title: "hardcoded API key"},
			}),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false when zero_tolerance_checks is a string, not an array")
		}
		if !containsReason(decision.Reasons, "invalid data.config.zero_tolerance_checks") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("zero_tolerance_checks as an empty array denies instead of allowing secrets", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"zero_tolerance_checks": []string{},
		}))
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, []types.Finding{
				{ID: "S1", Severity: types.SeverityLow, Title: "hardcoded API key"},
			}),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false when zero_tolerance_checks is an empty array")
		}
		if !containsReason(decision.Reasons, "invalid data.config.zero_tolerance_checks") {
			t.Errorf("expected an invalid-config deny reason, got %v", decision.Reasons)
		}
	})

	t.Run("valid config still allows deployment", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks":       []string{"sast", "secret"},
			"fail_on_severity":      "high",
			"zero_tolerance_checks": []string{"secret"},
		}))
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true for a well-formed config, got false; reasons=%v", decision.Reasons)
		}
	})
}

// TestPolicyFailClosedOnUnrecognizedSeverity covers the fail-open defect
// where a finding with a severity not present in severity_rank (a typo, an
// unsupported scale, an empty string) was silently ignored because the
// comparison against blocking_threshold was undefined.
func TestPolicyFailClosedOnUnrecognizedSeverity(t *testing.T) {
	ctx := context.Background()

	cases := []string{"HIGH", "Critical", "", "extreme"}
	for _, sev := range cases {
		t.Run("severity="+sev, func(t *testing.T) {
			e := policy.NewEvaluator("")
			atts := []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "U1", Severity: types.Severity(sev), Title: "unrecognized severity finding"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
				buildAttestation(types.CheckSecret, true, nil),
			}
			decision, err := e.Evaluate(ctx, buildInput(atts))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if decision.Allow {
				t.Errorf("expected Allow=false for unrecognized severity %q, got true", sev)
			}
			if !containsReason(decision.Reasons, "unrecognized severity") {
				t.Errorf("expected an unrecognized-severity deny reason, got %v", decision.Reasons)
			}
		})
	}

	t.Run("recognized severities do not trigger the unrecognized-severity reason", func(t *testing.T) {
		e := policy.NewEvaluator("")
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, true, []types.Finding{
				{ID: "I1", Severity: types.SeverityInfo, Title: "info finding"},
			}),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
			buildAttestation(types.CheckSecret, true, nil),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("expected Allow=true for a recognized low severity finding, got false; reasons=%v", decision.Reasons)
		}
		if containsReason(decision.Reasons, "unrecognized severity") {
			t.Errorf("did not expect an unrecognized-severity reason, got %v", decision.Reasons)
		}
	})
}

func TestDefaultPolicyRego(t *testing.T) {
	ctx := context.Background()

	// Verify the DefaultPolicy string compiles without error.
	e := policy.NewEvaluator("")
	input := buildInput([]types.Attestation{
		buildAttestation(types.CheckSAST, true, nil),
		buildAttestation(types.CheckSCA, true, nil),
		buildAttestation(types.CheckConfig, true, nil),
		buildAttestation(types.CheckSecret, true, nil),
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
			name: "all four required checks passed, no findings",
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
			name: "medium findings on a non-secret check do not block",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "M1", Severity: types.SeverityMedium, Title: "medium issue"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
				buildAttestation(types.CheckSecret, true, nil),
			},
			wantAllow:   true,
			wantReasons: []string{"all checks passed"},
		},
		{
			name: "high severity findings on a non-secret check block deployment by default",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, []types.Finding{
					{ID: "H1", Severity: types.SeverityHigh, Title: "high issue"},
				}),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
				buildAttestation(types.CheckSecret, true, nil),
			},
			wantAllow:   false,
			wantReasons: []string{`found 1 finding(s) at or above "high" severity`},
		},
		{
			name: "any secret-scan finding blocks deployment regardless of severity",
			attestations: []types.Attestation{
				buildAttestation(types.CheckSAST, true, nil),
				buildAttestation(types.CheckSCA, true, nil),
				buildAttestation(types.CheckConfig, true, nil),
				buildAttestation(types.CheckSecret, true, []types.Finding{
					{ID: "S1", Severity: types.SeverityLow, Title: "hardcoded API key"},
				}),
			},
			wantAllow:   false,
			wantReasons: []string{"hardcoded credential finding"},
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
			wantReasons: []string{`found 1 finding(s) at or above "high" severity`},
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
			wantReasons: []string{`found 1 finding(s) at or above "high" severity`, "missing required checks"},
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

	t.Run("deny_reasons with import rego.v1 returns array not map", func(t *testing.T) {
		// With `import rego.v1`, OPA returns sets as []interface{} not map[string]interface{}.
		// This test guards against the type-assertion bug that caused reasons to be silently nil.
		regoV1Policy := `
package devsecops.gate

import rego.v1

default allow := false

sast_passed if {
    some a in input.attestations
    a.result.check_type == "sast"
    a.result.passed == true
}

deny_reasons contains "SAST did not pass" if not sast_passed
`
		e := policy.NewEvaluator(regoV1Policy)
		atts := []types.Attestation{
			buildAttestation(types.CheckSAST, false, nil),
			buildAttestation(types.CheckSCA, true, nil),
			buildAttestation(types.CheckConfig, true, nil),
		}
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("expected Allow=false")
		}
		if !containsReason(decision.Reasons, "SAST did not pass") {
			t.Errorf("reasons %v should contain 'SAST did not pass'", decision.Reasons)
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
		buildAttestation(types.CheckSecret, true, nil),
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
			buildSignedAttestation(t, types.CheckSecret, true, nil, kp),
		}
		input := types.PolicyInput{
			Subject:      attestations[0].Subject,
			Attestations: attestations,
			AuthorizedSigners: map[string]string{
				"sast":   pubHex,
				"sca":    pubHex,
				"config": pubHex,
				"secret": pubHex,
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
			buildSignedAttestation(t, types.CheckSecret, true, nil, kp),
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
			buildSignedAttestation(t, types.CheckSecret, true, nil, kp),
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
		// Only SAST signer is constrained; SCA, Config, and Secret can use any key.
		attestations := []types.Attestation{
			buildSignedAttestation(t, types.CheckSAST, true, nil, kp),
			buildSignedAttestation(t, types.CheckSCA, true, nil, kpOther),    // different key, not constrained
			buildSignedAttestation(t, types.CheckConfig, true, nil, kpOther), // different key, not constrained
			buildSignedAttestation(t, types.CheckSecret, true, nil, kpOther), // different key, not constrained
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

// TestChainSealedAgainstUndeclaredCheckTruncation covers the tail-truncation
// attack: an attacker who can drop a trailing attestation from an otherwise
// verified chain must not be able to hide a failing check by truncating it
// off, when that check type would otherwise be caught by required_checks.
//
// A check type that is not declared in required_checks at all is rejected
// outright ("undeclared check types") the moment it appears in the chain,
// regardless of whether it passed - so truncating it away is a no-op from
// the policy's perspective (the untruncated chain was already denied for a
// stronger reason than the truncated one would have been allowed for). Once
// an operator declares a custom check type in required_checks, truncating
// it away is caught by "missing required checks" instead.
func TestChainSealedAgainstUndeclaredCheckTruncation(t *testing.T) {
	ctx := context.Background()
	license := types.SecurityCheckType("license")

	cleanFour := []types.Attestation{
		buildAttestation(types.CheckSAST, true, nil),
		buildAttestation(types.CheckSCA, true, nil),
		buildAttestation(types.CheckConfig, true, nil),
		buildAttestation(types.CheckSecret, true, nil),
	}
	failingLicense := buildAttestation(license, false, []types.Finding{
		{ID: "L1", Severity: types.SeverityHigh, Title: "GPL dependency"},
	})

	t.Run("license undeclared: full chain denies as undeclared check type", func(t *testing.T) {
		e := policy.NewEvaluator("")
		atts := append(append([]types.Attestation{}, cleanFour...), failingLicense)
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("Allow=true, want false: license is not a declared required check")
		}
		if !containsReason(decision.Reasons, "undeclared check types") {
			t.Errorf("reasons %v do not mention undeclared check types", decision.Reasons)
		}
	})

	t.Run("license undeclared: truncated chain allows (license was never part of the contract)", func(t *testing.T) {
		e := policy.NewEvaluator("")
		decision, err := e.Evaluate(ctx, buildInput(cleanFour))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !decision.Allow {
			t.Errorf("Allow=false, want true: default required_checks does not include license; reasons=%v", decision.Reasons)
		}
	})

	t.Run("license declared: full chain denies for the failing license check", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": []string{"sast", "sca", "config", "secret", "license"},
		}))
		atts := append(append([]types.Attestation{}, cleanFour...), failingLicense)
		decision, err := e.Evaluate(ctx, buildInput(atts))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("Allow=true, want false: license check failed and is required")
		}
		if containsReason(decision.Reasons, "undeclared check types") {
			t.Errorf("license is declared, should not be reported as undeclared; reasons=%v", decision.Reasons)
		}
	})

	t.Run("license declared: truncated chain denies as a missing required check", func(t *testing.T) {
		e := policy.NewEvaluator("", policy.WithData(map[string]any{
			"required_checks": []string{"sast", "sca", "config", "secret", "license"},
		}))
		decision, err := e.Evaluate(ctx, buildInput(cleanFour))
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if decision.Allow {
			t.Error("Allow=true, want false: license is required but was truncated from the chain")
		}
		if !containsReason(decision.Reasons, "missing required checks") {
			t.Errorf("reasons %v do not mention missing required checks", decision.Reasons)
		}
	})
}
