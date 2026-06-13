package policy_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/policy"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// loadDeployRego returns the source of .github/policies/deploy.rego from the
// repo root.  The test runs from internal/policy/, so we walk up two dirs.
func loadDeployRego(tb testing.TB) string {
	tb.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	// thisFile is internal/policy/evaluator_bench_test.go; go up two levels.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	policyPath := filepath.Join(repoRoot, ".github", "policies", "deploy.rego")
	b, err := os.ReadFile(policyPath)
	if err != nil {
		tb.Fatalf("reading deploy.rego (%s): %v", policyPath, err)
	}
	return string(b)
}

// buildBenchPolicyInput builds a PolicyInput with n attestations.
// Each attestation uses a unique synthetic check-type ("check-0", "check-1", …)
// so the deploy.rego "missing required checks" rule fires (the policy expects
// "sast", "sca", "config") — the benchmark measures evaluation latency rather
// than the allow/deny outcome, so this is fine.
//
// For completeness the first three attestations always use the standard
// check types required by deploy.rego, so an input of n >= 3 allows
// deployment.  Attestations 4…n use synthetic names.
func buildBenchPolicyInput(n int) types.PolicyInput {
	now := time.Now().UTC()
	attestations := make([]types.Attestation, n)

	// Standard check types that deploy.rego requires.
	standard := []types.SecurityCheckType{
		types.CheckSAST,
		types.CheckSCA,
		types.CheckConfig,
	}

	for i := 0; i < n; i++ {
		var ct types.SecurityCheckType
		if i < len(standard) {
			ct = standard[i]
		} else {
			ct = types.SecurityCheckType(fmt.Sprintf("extra-check-%d", i))
		}
		attestations[i] = types.Attestation{
			ID: fmt.Sprintf("bench-policy-id-%06d", i),
			Subject: types.AttestationSubject{
				Name:   "bench-app",
				Digest: "sha256:benchpolicy",
			},
			Result: types.SecurityResult{
				CheckType:   ct,
				Tool:        "bench-tool",
				Version:     "1.0.0",
				TargetRef:   "benchref",
				RunAt:       now,
				PassedCount: 1,
				Findings:    []types.Finding{},
				Passed:      true,
			},
			Timestamp:      now,
			SignerPublicKey: []byte{},
		}
	}

	return types.PolicyInput{
		Subject: types.AttestationSubject{
			Name:   "bench-app",
			Digest: "sha256:benchpolicy",
		},
		Attestations: attestations,
		RunAt:        now,
	}
}

// BenchmarkEvaluate measures policy evaluation with the real deploy.rego
// policy for input sizes N ∈ {1, 4, 16, 64, 256, 1024}.
// The Evaluator is constructed and the PolicyInput is built outside the timed
// loop; only the Evaluate call is measured.
func BenchmarkEvaluate(b *testing.B) {
	policySource := loadDeployRego(b)
	sizes := []int{1, 4, 16, 64, 256, 1024}

	for _, n := range sizes {
		n := n // capture
		e := policy.NewEvaluator(policySource)
		input := buildBenchPolicyInput(n)
		ctx := context.Background()

		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Evaluate(ctx, input); err != nil {
					b.Fatalf("Evaluate(N=%d): %v", n, err)
				}
			}
		})
	}
}
