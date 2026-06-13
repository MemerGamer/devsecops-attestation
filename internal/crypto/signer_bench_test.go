package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha256" // ensure SHA-256 is registered
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// representativeAttestation builds a realistic attestation whose canonical
// payload is used as the signing payload for all algorithm benchmarks.
func representativeAttestation() *types.Attestation {
	return &types.Attestation{
		ID: "bench-id-00000000-0000-0000-0000-000000000001",
		Subject: types.AttestationSubject{
			Name:   "myapp",
			Digest: "sha256:4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
		},
		Result: types.SecurityResult{
			CheckType:   types.CheckSAST,
			Tool:        "semgrep",
			Version:     "1.50.0",
			TargetRef:   "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
			RunAt:       time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
			PassedCount: 42,
			Findings: []types.Finding{
				{ID: "F001", Severity: types.SeverityHigh, Title: "SQL injection risk", Location: "main.go:42"},
				{ID: "F002", Severity: types.SeverityMedium, Title: "XSS in template", Location: "view.go:17"},
			},
			Passed: true,
		},
		Timestamp:      time.Date(2024, 6, 1, 12, 1, 0, 0, time.UTC),
		PreviousDigest: "",
		SignerID:       "github-runner:ubuntu-22.04",
	}
}

// BenchmarkKeygen_Ed25519 measures Ed25519 key-pair generation.
func BenchmarkKeygen_Ed25519(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKeyPair(); err != nil {
			b.Fatalf("GenerateKeyPair: %v", err)
		}
	}
}

// BenchmarkSign_Ed25519 measures Ed25519 signing of the canonical attestation payload.
func BenchmarkSign_Ed25519(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("setup: GenerateKeyPair: %v", err)
	}
	a := representativeAttestation()
	// Compute the payload once to confirm it works, then reset.
	if err := Sign(a, kp); err != nil {
		b.Fatalf("setup: Sign: %v", err)
	}
	// Use a fresh attestation each iteration to avoid stale-signature effects.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bench := representativeAttestation()
		if err := Sign(bench, kp); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

// BenchmarkVerify_Ed25519 measures Ed25519 signature verification.
func BenchmarkVerify_Ed25519(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("setup: GenerateKeyPair: %v", err)
	}
	a := representativeAttestation()
	if err := Sign(a, kp); err != nil {
		b.Fatalf("setup: Sign: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(a); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// BenchmarkKeygen_ECDSAP256 measures ECDSA P-256 key-pair generation.
func BenchmarkKeygen_ECDSAP256(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			b.Fatalf("ECDSA GenerateKey: %v", err)
		}
	}
}

// BenchmarkSign_ECDSAP256 measures ECDSA P-256 signing over SHA-256 of the canonical payload.
func BenchmarkSign_ECDSAP256(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("setup: ECDSA GenerateKey: %v", err)
	}
	a := representativeAttestation()
	payload, err := CanonicalPayload(a)
	if err != nil {
		b.Fatalf("setup: CanonicalPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:]); err != nil {
			b.Fatalf("ECDSA Sign: %v", err)
		}
	}
}

// BenchmarkVerify_ECDSAP256 measures ECDSA P-256 signature verification.
func BenchmarkVerify_ECDSAP256(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("setup: ECDSA GenerateKey: %v", err)
	}
	a := representativeAttestation()
	payload, err := CanonicalPayload(a)
	if err != nil {
		b.Fatalf("setup: CanonicalPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		b.Fatalf("setup: ECDSA Sign: %v", err)
	}
	pubKey := &privKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
			b.Fatal("ECDSA Verify failed")
		}
	}
}

// BenchmarkKeygen_RSA2048 measures RSA-2048 key-pair generation.
func BenchmarkKeygen_RSA2048(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
			b.Fatalf("RSA GenerateKey: %v", err)
		}
	}
}

// BenchmarkSign_RSA2048 measures RSA-2048 PSS signing over SHA-256 of the canonical payload.
func BenchmarkSign_RSA2048(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("setup: RSA GenerateKey: %v", err)
	}
	a := representativeAttestation()
	payload, err := CanonicalPayload(a)
	if err != nil {
		b.Fatalf("setup: CanonicalPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	opts := &rsa.PSSOptions{Hash: gocrypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rsa.SignPSS(rand.Reader, privKey, gocrypto.SHA256, digest[:], opts); err != nil {
			b.Fatalf("RSA Sign: %v", err)
		}
	}
}

// BenchmarkVerify_RSA2048 measures RSA-2048 PSS signature verification.
func BenchmarkVerify_RSA2048(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("setup: RSA GenerateKey: %v", err)
	}
	a := representativeAttestation()
	payload, err := CanonicalPayload(a)
	if err != nil {
		b.Fatalf("setup: CanonicalPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	opts := &rsa.PSSOptions{Hash: gocrypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	sig, err := rsa.SignPSS(rand.Reader, privKey, gocrypto.SHA256, digest[:], opts)
	if err != nil {
		b.Fatalf("setup: RSA Sign: %v", err)
	}
	pubKey := &privKey.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rsa.VerifyPSS(pubKey, gocrypto.SHA256, digest[:], sig, opts); err != nil {
			b.Fatalf("RSA Verify: %v", err)
		}
	}
}

// TestEmitKeySizes records per-algorithm signature size and public-key size to
// benchmarks/results/key_sizes.csv. It is a plain test (not a benchmark) so it
// runs with "go test -run TestEmitKeySizes".
func TestEmitKeySizes(t *testing.T) {
	// Resolve the repo root: this test lives in internal/crypto/, so go up two directories.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	outDir := filepath.Join(repoRoot, "benchmarks", "results")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%s): %v", outDir, err)
	}
	outPath := filepath.Join(outDir, "key_sizes.csv")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("os.Create(%s): %v", outPath, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"algorithm", "sig_bytes", "pubkey_bytes"}); err != nil {
		t.Fatalf("csv header: %v", err)
	}

	a := representativeAttestation()
	payload, err := CanonicalPayload(a)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	digest := sha256.Sum256(payload)

	// Ed25519
	{
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Ed25519 GenerateKeyPair: %v", err)
		}
		if err := Sign(a, kp); err != nil {
			t.Fatalf("Ed25519 Sign: %v", err)
		}
		sigSize := len(a.Signature)
		pubSize := len(kp.PublicKey)
		if err := w.Write([]string{"Ed25519", fmt.Sprintf("%d", sigSize), fmt.Sprintf("%d", pubSize)}); err != nil {
			t.Fatalf("csv Ed25519: %v", err)
		}
	}

	// ECDSA P-256
	{
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ECDSA GenerateKey: %v", err)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
		if err != nil {
			t.Fatalf("ECDSA Sign: %v", err)
		}
		// Public key in uncompressed form: 04 || X || Y = 65 bytes for P-256
		pubBytes := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
		if err := w.Write([]string{"ECDSA-P256", fmt.Sprintf("%d", len(sig)), fmt.Sprintf("%d", len(pubBytes))}); err != nil {
			t.Fatalf("csv ECDSA-P256: %v", err)
		}
	}

	// RSA-2048
	{
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("RSA GenerateKey: %v", err)
		}
		opts := &rsa.PSSOptions{Hash: gocrypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
		sig, err := rsa.SignPSS(rand.Reader, privKey, gocrypto.SHA256, digest[:], opts)
		if err != nil {
			t.Fatalf("RSA Sign: %v", err)
		}
		// Public key modulus bytes = key size / 8 = 256 bytes for RSA-2048
		pubBytes := privKey.PublicKey.N.BitLen() / 8
		if err := w.Write([]string{"RSA-2048", fmt.Sprintf("%d", len(sig)), fmt.Sprintf("%d", pubBytes)}); err != nil {
			t.Fatalf("csv RSA-2048: %v", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatalf("csv flush: %v", err)
	}
	t.Logf("key_sizes.csv written to %s", outPath)
}
