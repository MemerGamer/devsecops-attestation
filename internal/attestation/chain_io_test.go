package attestation

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// buildTestChain creates n signed attestations for IO tests.
func buildTestChain(t testing.TB, n int) []types.Attestation {
	t.Helper()
	kp := makeKeyPair(t)
	c := NewChain()
	checkTypes := []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig}
	for i := 0; i < n; i++ {
		result := types.SecurityResult{
			CheckType:   checkTypes[i%len(checkTypes)],
			Tool:        "semgrep",
			Version:     "1.0.0",
			TargetRef:   "abc123",
			RunAt:       time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			PassedCount: 1,
			Findings:    []types.Finding{},
			Passed:      true,
		}
		c.Add(makeSubject("app"), result, kp) //nolint
	}
	return c.Attestations()
}

func TestLoadChain(t *testing.T) {
	t.Run("nonexistent file returns empty slice", func(t *testing.T) {
		result, err := LoadChain("/tmp/nonexistent-chain-file-that-does-not-exist-12345.json")
		if err != nil {
			t.Errorf("LoadChain() unexpected error = %v", err)
		}
		if result == nil {
			t.Error("LoadChain() returned nil, want empty slice")
		}
		if len(result) != 0 {
			t.Errorf("LoadChain() returned %d items, want 0", len(result))
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("this is not json {{{"), 0o644); err != nil {
			t.Fatalf("setup: WriteFile error = %v", err)
		}
		_, err := LoadChain(path)
		if err == nil {
			t.Error("LoadChain() expected error for invalid JSON, got nil")
		}
	})
}

func TestSaveAndLoadChain(t *testing.T) {
	t.Run("save and load round-trip preserves data", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "chain.json")

		original := buildTestChain(t, 3)
		if err := SaveChain(path, original); err != nil {
			t.Fatalf("SaveChain() error = %v", err)
		}

		loaded, err := LoadChain(path)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}

		if len(loaded) != len(original) {
			t.Fatalf("loaded %d attestations, want %d", len(loaded), len(original))
		}

		for i := range original {
			if loaded[i].ID != original[i].ID {
				t.Errorf("[%d] ID mismatch: loaded %q, original %q", i, loaded[i].ID, original[i].ID)
			}
			if loaded[i].PreviousDigest != original[i].PreviousDigest {
				t.Errorf("[%d] PreviousDigest mismatch", i)
			}
			if loaded[i].Result.CheckType != original[i].Result.CheckType {
				t.Errorf("[%d] CheckType mismatch", i)
			}
			if len(loaded[i].Signature) != len(original[i].Signature) {
				t.Errorf("[%d] Signature length mismatch", i)
			}
			if len(loaded[i].SignerPublicKey) != len(original[i].SignerPublicKey) {
				t.Errorf("[%d] SignerPublicKey length mismatch", i)
			}
		}
	})

	t.Run("chain file is valid indented JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "chain.json")

		original := buildTestChain(t, 1)
		if err := SaveChain(path, original); err != nil {
			t.Fatalf("SaveChain() error = %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		// Indented JSON has newlines.
		content := string(data)
		if len(content) == 0 {
			t.Error("saved file is empty")
		}
		// First character of JSON array should be '['.
		if content[0] != '[' {
			t.Errorf("saved file does not start with '[': %q", content[:10])
		}
	})

	t.Run("signatures survive round-trip and verify correctly", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "chain.json")

		original := buildTestChain(t, 2)
		if err := SaveChain(path, original); err != nil {
			t.Fatalf("SaveChain() error = %v", err)
		}

		loaded, err := LoadChain(path)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}

		_, err = VerifyChain(loaded)
		if err != nil {
			t.Errorf("VerifyChain() on loaded chain error = %v", err)
		}
	})
}
