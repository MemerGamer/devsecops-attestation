package attestation

import (
	"fmt"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// buildBenchChain builds a valid signed chain of n attestations outside the
// timed loop.  Each attestation uses a unique synthetic check-type string
// ("check-0", "check-1", …) to satisfy the no-duplicate-check-types rule in
// VerifyChainWithOptions for chains longer than the 4 standard check types.
// A fixed reference time is passed so that no future-timestamp errors arise
// regardless of when the benchmark runs.
func buildBenchChain(b *testing.B, n int) []types.Attestation {
	b.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}

	baseTime := time.Now().UTC().Add(-time.Duration(n) * time.Second)

	attestations := make([]types.Attestation, 0, n)
	var prevDigest string

	for i := 0; i < n; i++ {
		checkType := types.SecurityCheckType(fmt.Sprintf("check-%d", i))
		ts := baseTime.Add(time.Duration(i) * time.Second)

		a := &types.Attestation{
			ID: fmt.Sprintf("bench-id-%06d", i),
			Subject: types.AttestationSubject{
				Name:   "bench-app",
				Digest: "sha256:bench",
			},
			Result: types.SecurityResult{
				CheckType:   checkType,
				Tool:        "bench-tool",
				Version:     "1.0.0",
				TargetRef:   "benchref",
				RunAt:       ts,
				PassedCount: 1,
				Findings:    []types.Finding{},
				Passed:      true,
			},
			Timestamp:      ts,
			PreviousDigest: prevDigest,
		}

		if err := crypto.Sign(a, kp); err != nil {
			b.Fatalf("Sign at index %d: %v", i, err)
		}

		digest, err := crypto.Digest(a)
		if err != nil {
			b.Fatalf("Digest at index %d: %v", i, err)
		}

		attestations = append(attestations, *a)
		prevDigest = digest
	}

	return attestations
}

// BenchmarkVerifyChain measures VerifyChainWithOptions for chain lengths
// N ∈ {1, 4, 16, 64, 256, 1024}.  Chain construction happens outside the
// timed loop; only the verification call is measured.
func BenchmarkVerifyChain(b *testing.B) {
	sizes := []int{1, 4, 16, 64, 256, 1024}

	for _, n := range sizes {
		n := n // capture
		chain := buildBenchChain(b, n)
		// Use a fixed Now well in the future of the chain so no age errors arise.
		opts := VerifyOptions{
			Now: time.Now().UTC().Add(24 * time.Hour),
		}

		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyChainWithOptions(chain, opts); err != nil {
					b.Fatalf("VerifyChainWithOptions(N=%d): %v", n, err)
				}
			}
		})
	}
}
