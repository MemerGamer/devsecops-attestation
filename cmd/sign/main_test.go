package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
)

func generateTestKey(t testing.TB) (privHex, pubHex string) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return hex.EncodeToString([]byte(kp.PrivateKey)), hex.EncodeToString([]byte(kp.PublicKey))
}

func TestRunSign(t *testing.T) {
	ctx := context.Background()
	resultFile := filepath.Join("testdata", "sast-result.json")

	t.Run("first sign creates chain with one attestation", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if len(chain) != 1 {
			t.Errorf("chain length = %d, want 1", len(chain))
		}
		if chain[0].Result.CheckType != "sast" {
			t.Errorf("CheckType = %q, want sast", chain[0].Result.CheckType)
		}
	})

	t.Run("second sign appends to chain with correct linkage", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		baseFlags := signFlags{
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
		}

		f1 := baseFlags
		f1.checkType = "sast"
		if err := runSign(ctx, f1); err != nil {
			t.Fatalf("first runSign() error = %v", err)
		}

		f2 := baseFlags
		f2.checkType = "sca"
		f2.tool = "trivy"
		if err := runSign(ctx, f2); err != nil {
			t.Fatalf("second runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if len(chain) != 2 {
			t.Fatalf("chain length = %d, want 2", len(chain))
		}

		expectedDigest, err := crypto.Digest(&chain[0])
		if err != nil {
			t.Fatalf("Digest() error = %v", err)
		}
		if chain[1].PreviousDigest != expectedDigest {
			t.Errorf("chain[1].PreviousDigest mismatch: got %q, want %q",
				chain[1].PreviousDigest, expectedDigest)
		}
	})

	t.Run("fails on invalid signing key hex", func(t *testing.T) {
		dir := t.TempDir()
		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: "not-valid-hex!!!!",
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Error("runSign() expected error for invalid hex, got nil")
		}
	})

	t.Run("fails on signing key with wrong length", func(t *testing.T) {
		dir := t.TempDir()
		shortKey := hex.EncodeToString(make([]byte, 32)) // 32 bytes, not 64
		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: shortKey,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Error("runSign() expected error for short key, got nil")
		}
	})

	t.Run("fails if result file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)
		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: filepath.Join(dir, "nonexistent.json"),
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Error("runSign() expected error for missing result file, got nil")
		}
	})

	t.Run("fails on unknown check type", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)
		err := runSign(ctx, signFlags{
			checkType:  "unknown-type",
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Error("runSign() expected error for unknown check type, got nil")
		}
	})

	t.Run("writes to --out when specified", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		outPath := filepath.Join(dir, "chain-out.json")
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: resultFile,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
			out:        outPath,
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		if _, err := os.Stat(outPath); os.IsNotExist(err) {
			t.Error("--out file was not created")
		}
		if _, err := os.Stat(chainPath); err == nil {
			t.Error("--chain file should not have been created when --out is set")
		}
	})
}
