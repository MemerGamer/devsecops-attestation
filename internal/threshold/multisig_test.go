package threshold_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/internal/threshold"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func newTestAttestation(t *testing.T) *types.Attestation {
	t.Helper()
	return &types.Attestation{
		ID: "test-id-1",
		Subject: types.AttestationSubject{
			Name:   "myapp",
			Digest: "sha256:abc123",
		},
		Result: types.SecurityResult{
			CheckType: types.CheckSAST,
			Tool:      "semgrep",
			Version:   "1.0.0",
			TargetRef: "abc123",
			RunAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Findings:  []types.Finding{},
			Passed:    true,
		},
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func mustKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return kp
}

func TestThresholdConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     threshold.ThresholdConfig
		wantErr bool
	}{
		{
			name:    "valid 2-of-3",
			cfg:     threshold.ThresholdConfig{Threshold: 2, Participants: 3},
			wantErr: false,
		},
		{
			name:    "valid 1-of-1",
			cfg:     threshold.ThresholdConfig{Threshold: 1, Participants: 1},
			wantErr: false,
		},
		{
			name:    "threshold zero",
			cfg:     threshold.ThresholdConfig{Threshold: 0, Participants: 3},
			wantErr: true,
		},
		{
			name:    "threshold exceeds participants",
			cfg:     threshold.ThresholdConfig{Threshold: 3, Participants: 2},
			wantErr: true,
		},
		{
			name:    "threshold equals participants",
			cfg:     threshold.ThresholdConfig{Threshold: 3, Participants: 3},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSimpleParticipantSign(t *testing.T) {
	kp := mustKeyPair(t)
	p := threshold.NewSimpleParticipant("participant-1", kp)

	if p.ID() != "participant-1" {
		t.Errorf("ID() = %q, want %q", p.ID(), "participant-1")
	}

	a := newTestAttestation(t)
	ps, err := p.Sign(a)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if ps.ParticipantID != "participant-1" {
		t.Errorf("ParticipantID = %q, want %q", ps.ParticipantID, "participant-1")
	}
	if len(ps.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey length = %d, want %d", len(ps.PublicKey), ed25519.PublicKeySize)
	}
	if len(ps.Partial) != ed25519.SignatureSize {
		t.Errorf("Partial length = %d, want %d", len(ps.Partial), ed25519.SignatureSize)
	}

	// Verify the partial signature is a valid Ed25519 signature over CanonicalPayload.
	payload, err := crypto.CanonicalPayload(a)
	if err != nil {
		t.Fatalf("CanonicalPayload() error = %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(ps.PublicKey), payload, ps.Partial) {
		t.Error("Partial is not a valid Ed25519 signature over CanonicalPayload")
	}
}

func TestSimpleParticipantSign_PublicKeyMatchesKeyPair(t *testing.T) {
	kp := mustKeyPair(t)
	p := threshold.NewSimpleParticipant("p1", kp)
	a := newTestAttestation(t)

	ps, err := p.Sign(a)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if !threshold.BytesEqual(ps.PublicKey, []byte(kp.PublicKey)) {
		t.Error("PartialSignature.PublicKey does not match the participant's public key")
	}
}

func TestSimpleAggregatorAggregate(t *testing.T) {
	cfg := threshold.ThresholdConfig{Threshold: 2, Participants: 3}
	a := newTestAttestation(t)

	kp1, kp2, kp3 := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	p1 := threshold.NewSimpleParticipant("alice", kp1)
	p2 := threshold.NewSimpleParticipant("bob", kp2)
	p3 := threshold.NewSimpleParticipant("carol", kp3)

	ps1, _ := p1.Sign(a)
	ps2, _ := p2.Sign(a)
	ps3, _ := p3.Sign(a)

	agg := threshold.SimpleAggregator{}

	t.Run("2-of-3 success with all three signatures", func(t *testing.T) {
		combined, err := agg.Aggregate([]threshold.PartialSignature{*ps1, *ps2, *ps3}, cfg)
		if err != nil {
			t.Errorf("Aggregate() error = %v", err)
		}
		if len(combined) == 0 {
			t.Error("combined output is empty")
		}
	})

	t.Run("2-of-3 success with exactly two signatures", func(t *testing.T) {
		combined, err := agg.Aggregate([]threshold.PartialSignature{*ps1, *ps2}, cfg)
		if err != nil {
			t.Errorf("Aggregate() error = %v", err)
		}
		if len(combined) == 0 {
			t.Error("combined output is empty")
		}
	})

	t.Run("threshold not met with one signature", func(t *testing.T) {
		_, err := agg.Aggregate([]threshold.PartialSignature{*ps1}, cfg)
		if err != threshold.ErrThresholdNotMet {
			t.Errorf("Aggregate() error = %v, want ErrThresholdNotMet", err)
		}
	})

	t.Run("threshold not met with empty signatures", func(t *testing.T) {
		_, err := agg.Aggregate([]threshold.PartialSignature{}, cfg)
		if err != threshold.ErrThresholdNotMet {
			t.Errorf("Aggregate() error = %v, want ErrThresholdNotMet", err)
		}
	})

	t.Run("duplicate participant ID counts as one", func(t *testing.T) {
		// ps1 duplicated three times - all from "alice" - should count as 1
		_, err := agg.Aggregate([]threshold.PartialSignature{*ps1, *ps1, *ps1}, cfg)
		if err != threshold.ErrThresholdNotMet {
			t.Errorf("Aggregate() with duplicates error = %v, want ErrThresholdNotMet", err)
		}
	})

	t.Run("output is deterministic (sorted by participant ID)", func(t *testing.T) {
		// Providing in different order should produce same combined output.
		out1, err1 := agg.Aggregate([]threshold.PartialSignature{*ps2, *ps1}, cfg)
		out2, err2 := agg.Aggregate([]threshold.PartialSignature{*ps1, *ps2}, cfg)
		if err1 != nil || err2 != nil {
			t.Fatalf("Aggregate() errors: %v, %v", err1, err2)
		}
		if !threshold.BytesEqual(out1, out2) {
			t.Error("Aggregate() output is not deterministic")
		}
	})

	t.Run("invalid threshold config returns error", func(t *testing.T) {
		badCfg := threshold.ThresholdConfig{Threshold: 0, Participants: 3}
		_, err := agg.Aggregate([]threshold.PartialSignature{*ps1, *ps2}, badCfg)
		if err == nil {
			t.Error("Aggregate() with invalid config should return error")
		}
	})
}

func TestVerify(t *testing.T) {
	a := newTestAttestation(t)
	kp1, kp2 := mustKeyPair(t), mustKeyPair(t)
	p1 := threshold.NewSimpleParticipant("alice", kp1)
	p2 := threshold.NewSimpleParticipant("bob", kp2)
	ps1, _ := p1.Sign(a)
	ps2, _ := p2.Sign(a)
	cfg := threshold.ThresholdConfig{Threshold: 2, Participants: 2}

	t.Run("valid threshold passes", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2},
		}
		if err := threshold.Verify(ta); err != nil {
			t.Errorf("Verify() unexpected error = %v", err)
		}
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            threshold.ThresholdConfig{Threshold: 0, Participants: 2},
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2},
		}
		if err := threshold.Verify(ta); err == nil {
			t.Error("Verify() expected error for invalid config, got nil")
		}
	})

	t.Run("threshold not met returns ErrThresholdNotMet", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1}, // only 1 of 2 required
		}
		if err := threshold.Verify(ta); err != threshold.ErrThresholdNotMet {
			t.Errorf("Verify() error = %v, want ErrThresholdNotMet", err)
		}
	})
}

func TestVerifyThreshold(t *testing.T) {
	cfg := threshold.ThresholdConfig{Threshold: 2, Participants: 3}
	a := newTestAttestation(t)

	kp1, kp2, kp3 := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	p1 := threshold.NewSimpleParticipant("alice", kp1)
	p2 := threshold.NewSimpleParticipant("bob", kp2)
	p3 := threshold.NewSimpleParticipant("carol", kp3)

	ps1, _ := p1.Sign(a)
	ps2, _ := p2.Sign(a)
	ps3, _ := p3.Sign(a)

	t.Run("valid 2-of-3 passes", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err != nil {
			t.Errorf("VerifyThreshold() error = %v", err)
		}
	})

	t.Run("valid 3-of-3 passes", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2, *ps3},
		}
		if err := threshold.VerifyThreshold(ta); err != nil {
			t.Errorf("VerifyThreshold() error = %v", err)
		}
	})

	t.Run("threshold not met returns ErrThresholdNotMet", func(t *testing.T) {
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1},
		}
		if err := threshold.VerifyThreshold(ta); err != threshold.ErrThresholdNotMet {
			t.Errorf("VerifyThreshold() error = %v, want ErrThresholdNotMet", err)
		}
	})

	t.Run("tampered attestation payload causes signature verification failure", func(t *testing.T) {
		// Sign original attestation, then mutate the attestation in ThresholdAttestation.
		tampered := *a
		tampered.Result.Passed = false // change payload after signing

		ta := &threshold.ThresholdAttestation{
			Attestation:       tampered,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err == nil {
			t.Error("VerifyThreshold() should fail for tampered attestation payload")
		}
	})

	t.Run("wrong public key in partial signature causes failure", func(t *testing.T) {
		wrongKP := mustKeyPair(t)
		badPS := threshold.PartialSignature{
			ParticipantID: "alice",
			PublicKey:     []byte(wrongKP.PublicKey), // wrong key, signature still from kp1
			Partial:       ps1.Partial,
		}
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{badPS, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err == nil {
			t.Error("VerifyThreshold() should fail when public key does not match signature")
		}
	})

	t.Run("invalid public key length causes failure", func(t *testing.T) {
		badPS := threshold.PartialSignature{
			ParticipantID: "alice",
			PublicKey:     []byte("tooshort"),
			Partial:       ps1.Partial,
		}
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{badPS, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err == nil {
			t.Error("VerifyThreshold() should fail for invalid public key length")
		}
	})

	t.Run("invalid signature length causes failure", func(t *testing.T) {
		badPS := threshold.PartialSignature{
			ParticipantID: "alice",
			PublicKey:     ps1.PublicKey,
			Partial:       []byte("tooshort"),
		}
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{badPS, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err == nil {
			t.Error("VerifyThreshold() should fail for invalid signature length")
		}
	})

	t.Run("duplicate participant ID counts as one", func(t *testing.T) {
		// ps1 three times: all from "alice", so only 1 valid distinct signature.
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            cfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps1, *ps1},
		}
		if err := threshold.VerifyThreshold(ta); err != threshold.ErrThresholdNotMet {
			t.Errorf("VerifyThreshold() error = %v, want ErrThresholdNotMet", err)
		}
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		badCfg := threshold.ThresholdConfig{Threshold: 0, Participants: 3}
		ta := &threshold.ThresholdAttestation{
			Attestation:       *a,
			Config:            badCfg,
			PartialSignatures: []threshold.PartialSignature{*ps1, *ps2},
		}
		if err := threshold.VerifyThreshold(ta); err == nil {
			t.Error("VerifyThreshold() should fail for invalid config")
		}
	})
}
