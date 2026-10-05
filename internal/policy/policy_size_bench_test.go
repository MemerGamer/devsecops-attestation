package policy_test

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
	"github.com/open-policy-agent/opa/ast"
)

// R counts the baseline policy as one unit plus R-1 added rules. deploy.rego
// already has multiple AST rules, so total_rules reports the actual count.
// Contradictory input conditions make added deny rules non-matching for every
// input, while referencing the queried rule keeps them relevant to compilation.
func sizedPolicy(source string, r int) string {
	var out strings.Builder
	out.WriteString(source)
	for i := 1; i < r; i++ {
		fmt.Fprintf(&out, "\ndeny_reasons[\"size-rule-%06d\"] if {\n input.subject.name == \"size-rule-%06d\"\n input.subject.name != \"size-rule-%06d\"\n}\n", i, i, i)
	}
	return out.String()
}

func equalDecision(a, b *types.GateDecision) bool {
	ar, br := append([]string(nil), a.Reasons...), append([]string(nil), b.Reasons...)
	sort.Strings(ar)
	sort.Strings(br)
	return a.Allow == b.Allow && reflect.DeepEqual(ar, br)
}

func TestPolicySizeEquivalent(t *testing.T) {
	source := loadDeployRego(t)
	ctx := context.Background()
	baseline := policy.NewEvaluator(source)
	for _, r := range []int{1, 4, 16, 64, 256} {
		generated := sizedPolicy(source, r)
		baseModule, err := ast.ParseModule("baseline.rego", source)
		if err != nil {
			t.Fatal(err)
		}
		module, err := ast.ParseModule("sized.rego", generated)
		if err != nil {
			t.Fatal(err)
		}
		if len(module.Rules) != len(baseModule.Rules)+r-1 {
			t.Fatal("unexpected generated rule count")
		}
		for _, scenario := range []string{"allow", "missing", "failed", "critical", "secret", "unauthorized", "contradiction"} {
			input := buildBenchPolicyInput(4)
			switch scenario {
			case "missing":
				input.Attestations = input.Attestations[:3]
			case "failed":
				input.Attestations[0].Result.Passed = false
			case "critical":
				input.Attestations[0].Result.Findings = []types.Finding{{ID: "finding", Severity: types.SeverityCritical}}
			case "secret":
				input.Attestations[3].Result.Findings = []types.Finding{{ID: "finding", Severity: types.SeverityLow}}
			case "unauthorized":
				input.AuthorizedSigners = map[string]string{"sast": "wrong-key"}
			case "contradiction":
				input.Subject.Name = "size-rule-000001"
			}
			want, err := baseline.Evaluate(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := policy.NewEvaluator(generated).Evaluate(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if !equalDecision(want, got) {
				t.Fatalf("R%d/%s: got %+v, want %+v", r, scenario, got, want)
			}
		}
	}
}

// BenchmarkEvaluatePolicySize measures the production Evaluate call, including
// input conversion and parsing/compiling both queries on every iteration.
func BenchmarkEvaluatePolicySize(b *testing.B) {
	source := loadDeployRego(b)
	input := buildBenchPolicyInput(4)
	ctx := context.Background()
	for _, r := range []int{1, 4, 16, 64, 256} {
		generated := sizedPolicy(source, r)
		module, err := ast.ParseModule("sized.rego", generated)
		if err != nil {
			b.Fatal(err)
		}
		e := policy.NewEvaluator(generated)
		decision, err := e.Evaluate(ctx, input)
		if err != nil {
			b.Fatal(err)
		}
		if !decision.Allow {
			b.Fatalf("R%d: expected fixed input to allow: %+v", r, decision)
		}
		b.Run(fmt.Sprintf("R%d", r), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Evaluate(ctx, input); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(module.Rules)), "total_rules")
		})
	}
}
