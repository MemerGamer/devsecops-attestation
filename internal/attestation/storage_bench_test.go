package attestation

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// storageChain uses fixed-width IDs/check names and whole-second timestamps
// so random keys and the clock do not change the serialized size. Findings
// are empty; this measures envelope/linkage overhead, not scanner output.
func storageChain(tb testing.TB) []types.Attestation {
	tb.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		tb.Fatal(err)
	}
	chain := make([]types.Attestation, 1024)
	ts := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	previous := ""
	for i := range chain {
		a := &chain[i]
		*a = types.Attestation{
			ID:        fmt.Sprintf("00000000-0000-0000-0000-%012d", i),
			Subject:   types.AttestationSubject{Name: "bench-app", Digest: "sha256:" + string(bytes.Repeat([]byte("a"), 64))},
			Result:    types.SecurityResult{CheckType: types.SecurityCheckType(fmt.Sprintf("check-%06d", i)), Tool: "bench-tool", Version: "1.0.0", TargetRef: string(bytes.Repeat([]byte("a"), 40)), RunAt: ts, PassedCount: 42, Findings: []types.Finding{}, Passed: true},
			Timestamp: ts, PreviousDigest: previous, SignerID: "github-runner:ubuntu-22.04",
			LogEntry: "https://github.com/org/repo/actions/runs/12345",
		}
		if err := crypto.Sign(a, kp); err != nil {
			tb.Fatal(err)
		}
		previous, err = crypto.Digest(a)
		if err != nil {
			tb.Fatal(err)
		}
	}
	if _, err := VerifyChainWithOptions(chain, VerifyOptions{Now: ts}); err != nil {
		tb.Fatal(err)
	}
	return chain
}

// BenchmarkStorageSizes times compact JSON serialization. Size metrics and CSV
// come from compacting the actual SaveChain output outside the timed loop.
func BenchmarkStorageSizes(b *testing.B) {
	chain := storageChain(b)
	dir := b.TempDir()
	outPath := os.Getenv("STORAGE_SIZES_CSV")
	if outPath == "" {
		outPath = filepath.Join(dir, "storage_sizes.csv")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		b.Fatal(err)
	}
	rows := [][]string{{"n", "single_attestation_bytes", "linked_attestation_bytes", "attestations_bytes", "chain_bytes", "bytes_per_attestation"}}
	for _, n := range []int{1, 4, 16, 64, 256, 1024} {
		path := filepath.Join(dir, "chain.json")
		if err := SaveChain(path, chain[:n]); err != nil {
			b.Fatal(err)
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, saved); err != nil {
			b.Fatal(err)
		}
		expected, err := json.Marshal(chain[:n])
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(compact.Bytes(), expected) {
			b.Fatal("compact SaveChain differs from json.Marshal")
		}
		var singles []json.RawMessage
		if err := json.Unmarshal(compact.Bytes(), &singles); err != nil {
			b.Fatal(err)
		}
		total := 0
		for _, single := range singles {
			total += len(single)
		}
		if compact.Len() != total+n+1 {
			b.Fatal("unexpected JSON array overhead")
		}
		linked, err := json.Marshal(chain[1])
		if err != nil {
			b.Fatal(err)
		}
		rows = append(rows, []string{strconv.Itoa(n), strconv.Itoa(len(singles[0])), strconv.Itoa(len(linked)), strconv.Itoa(total), strconv.Itoa(compact.Len()), strconv.FormatFloat(float64(compact.Len())/float64(n), 'f', 3, 64)})
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := json.Marshal(chain[:n]); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(singles[0])), "bytes/single")
			b.ReportMetric(float64(compact.Len()), "bytes/chain")
		})
	}
	f, err := os.Create(outPath)
	if err != nil {
		b.Fatal(err)
	}
	w := csv.NewWriter(f)
	err = w.WriteAll(rows)
	closeErr := f.Close()
	if err != nil {
		b.Fatal(err)
	}
	if closeErr != nil {
		b.Fatal(closeErr)
	}
	b.Logf("storage sizes CSV: %s (default temporary output is removed after the run)", outPath)
}
