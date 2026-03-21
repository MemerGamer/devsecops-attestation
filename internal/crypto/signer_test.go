package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// newTestAttestation returns a minimal valid Attestation for use in tests.
// It does not set Signature or SignerPublicKey; call Sign to populate those.
func newTestAttestation(t testing.TB) *types.Attestation {
	t.Helper()
	return &types.Attestation{
		ID: "test-id-1234",
		Subject: types.AttestationSubject{
			Name:   "myapp",
			Digest: "sha256:abc123",
		},
		Result: types.SecurityResult{
			CheckType:   types.CheckSAST,
			Tool:        "semgrep",
			Version:     "1.0.0",
			TargetRef:   "abc123def456",
			RunAt:       time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			PassedCount: 5,
			Findings:    []types.Finding{},
			Passed:      true,
		},
		Timestamp:      time.Date(2024, 1, 15, 10, 1, 0, 0, time.UTC),
		PreviousDigest: "",
	}
}

func TestGenerateKeyPair(t *testing.T) {
	t.Run("generates valid key pair", func(t *testing.T) {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		if len(kp.PublicKey) != ed25519.PublicKeySize {
			t.Errorf("PublicKey length = %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
		}
		if len(kp.PrivateKey) != ed25519.PrivateKeySize {
			t.Errorf("PrivateKey length = %d, want %d", len(kp.PrivateKey), ed25519.PrivateKeySize)
		}
	})

	t.Run("two calls produce different keys", func(t *testing.T) {
		kp1, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("first GenerateKeyPair() error = %v", err)
		}
		kp2, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("second GenerateKeyPair() error = %v", err)
		}
		if bytes.Equal(kp1.PublicKey, kp2.PublicKey) {
			t.Error("two GenerateKeyPair() calls produced identical public keys")
		}
	})
}

func TestKeyPairFromBytes(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup: GenerateKeyPair() error = %v", err)
	}

	tests := []struct {
		name    string
		pub     []byte
		priv    []byte
		wantErr string
	}{
		{
			name:    "valid round-trip",
			pub:     []byte(kp.PublicKey),
			priv:    []byte(kp.PrivateKey),
			wantErr: "",
		},
		{
			name:    "pub too short (31 bytes)",
			pub:     make([]byte, 31),
			priv:    []byte(kp.PrivateKey),
			wantErr: "invalid public key length",
		},
		{
			name:    "pub too long (33 bytes)",
			pub:     make([]byte, 33),
			priv:    []byte(kp.PrivateKey),
			wantErr: "invalid public key length",
		},
		{
			name:    "priv too short (63 bytes)",
			pub:     []byte(kp.PublicKey),
			priv:    make([]byte, 63),
			wantErr: "invalid private key length",
		},
		{
			name:    "priv too long (65 bytes)",
			pub:     []byte(kp.PublicKey),
			priv:    make([]byte, 65),
			wantErr: "invalid private key length",
		},
		{
			name:    "empty public key",
			pub:     []byte{},
			priv:    []byte(kp.PrivateKey),
			wantErr: "invalid public key length",
		},
		{
			name:    "empty private key",
			pub:     []byte(kp.PublicKey),
			priv:    []byte{},
			wantErr: "invalid private key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyPairFromBytes(tt.pub, tt.priv)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("KeyPairFromBytes() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("KeyPairFromBytes() unexpected error = %v", err)
			}
			if !bytes.Equal(got.PublicKey, tt.pub) {
				t.Error("reconstructed PublicKey does not match input")
			}
			if !bytes.Equal(got.PrivateKey, tt.priv) {
				t.Error("reconstructed PrivateKey does not match input")
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup: GenerateKeyPair() error = %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup: second GenerateKeyPair() error = %v", err)
	}

	tests := []struct {
		name      string
		setup     func(*types.Attestation) // mutations applied after Sign
		signKP    *KeyPair
		wantErr   string // empty = expect nil from Verify
	}{
		{
			name:    "valid attestation",
			setup:   func(a *types.Attestation) {},
			signKP:  kp,
			wantErr: "",
		},
		{
			name: "tampered Result.Passed",
			setup: func(a *types.Attestation) {
				a.Result.Passed = !a.Result.Passed
			},
			signKP:  kp,
			wantErr: "tampered",
		},
		{
			name: "tampered ID",
			setup: func(a *types.Attestation) {
				a.ID = "hacked-id"
			},
			signKP:  kp,
			wantErr: "tampered",
		},
		{
			name: "tampered Timestamp",
			setup: func(a *types.Attestation) {
				a.Timestamp = a.Timestamp.Add(time.Second)
			},
			signKP:  kp,
			wantErr: "tampered",
		},
		{
			name: "tampered PreviousDigest",
			setup: func(a *types.Attestation) {
				a.PreviousDigest = "deadbeefdeadbeef"
			},
			signKP:  kp,
			wantErr: "tampered",
		},
		{
			name: "wrong SignerPublicKey bytes",
			setup: func(a *types.Attestation) {
				a.SignerPublicKey = []byte(kp2.PublicKey)
			},
			signKP:  kp,
			wantErr: "tampered",
		},
		{
			name: "truncated signature (32 bytes)",
			setup: func(a *types.Attestation) {
				a.Signature = a.Signature[:32]
			},
			signKP:  kp,
			wantErr: "invalid or missing signature",
		},
		{
			name: "nil signature",
			setup: func(a *types.Attestation) {
				a.Signature = nil
			},
			signKP:  kp,
			wantErr: "invalid or missing signature",
		},
		{
			name: "nil public key",
			setup: func(a *types.Attestation) {
				a.SignerPublicKey = nil
			},
			signKP:  kp,
			wantErr: "invalid or missing signer public key",
		},
		{
			name: "tampered finding title",
			setup: func(a *types.Attestation) {
				a.Result.Findings = append(a.Result.Findings, types.Finding{
					ID:       "new",
					Severity: types.SeverityCritical,
					Title:    "injected finding",
				})
			},
			signKP:  kp,
			wantErr: "tampered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAttestation(t)
			if err := Sign(a, tt.signKP); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			tt.setup(a)

			err := Verify(a)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Verify() unexpected error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify() expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Verify() error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSignIsDeterministic(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup: GenerateKeyPair() error = %v", err)
	}

	a1 := newTestAttestation(t)
	if err := Sign(a1, kp); err != nil {
		t.Fatalf("first Sign() error = %v", err)
	}
	sig1 := make([]byte, len(a1.Signature))
	copy(sig1, a1.Signature)

	// Sign the same attestation (same payload) again.
	a2 := newTestAttestation(t)
	if err := Sign(a2, kp); err != nil {
		t.Fatalf("second Sign() error = %v", err)
	}

	if !bytes.Equal(sig1, a2.Signature) {
		t.Error("Ed25519 signing is not deterministic: two identical payloads produced different signatures")
	}
}

func TestDigest(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup: GenerateKeyPair() error = %v", err)
	}

	t.Run("same attestation produces same digest", func(t *testing.T) {
		a := newTestAttestation(t)
		if err := Sign(a, kp); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		d1, err := Digest(a)
		if err != nil {
			t.Fatalf("first Digest() error = %v", err)
		}
		d2, err := Digest(a)
		if err != nil {
			t.Fatalf("second Digest() error = %v", err)
		}
		if d1 != d2 {
			t.Errorf("Digest() not deterministic: %q vs %q", d1, d2)
		}
	})

	t.Run("different attestations produce different digests", func(t *testing.T) {
		a1 := newTestAttestation(t)
		a1.ID = "id-1"
		if err := Sign(a1, kp); err != nil {
			t.Fatalf("Sign(a1) error = %v", err)
		}
		a2 := newTestAttestation(t)
		a2.ID = "id-2"
		if err := Sign(a2, kp); err != nil {
			t.Fatalf("Sign(a2) error = %v", err)
		}

		d1, err := Digest(a1)
		if err != nil {
			t.Fatalf("Digest(a1) error = %v", err)
		}
		d2, err := Digest(a2)
		if err != nil {
			t.Fatalf("Digest(a2) error = %v", err)
		}
		if d1 == d2 {
			t.Error("different attestations produced identical digests")
		}
	})

	t.Run("modifying a field changes the digest", func(t *testing.T) {
		a := newTestAttestation(t)
		if err := Sign(a, kp); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		before, err := Digest(a)
		if err != nil {
			t.Fatalf("Digest() before error = %v", err)
		}

		a.Result.Passed = !a.Result.Passed

		after, err := Digest(a)
		if err != nil {
			t.Fatalf("Digest() after error = %v", err)
		}
		if before == after {
			t.Error("mutating attestation did not change its digest")
		}
	})

	t.Run("digest is 64-character lowercase hex", func(t *testing.T) {
		a := newTestAttestation(t)
		if err := Sign(a, kp); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		d, err := Digest(a)
		if err != nil {
			t.Fatalf("Digest() error = %v", err)
		}
		if len(d) != 64 {
			t.Errorf("digest length = %d, want 64", len(d))
		}
		if d != strings.ToLower(d) {
			t.Error("digest is not lowercase")
		}
		if _, err := hex.DecodeString(d); err != nil {
			t.Errorf("digest %q is not valid hex: %v", d, err)
		}
	})
}
