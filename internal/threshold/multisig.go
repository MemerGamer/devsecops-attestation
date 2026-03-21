// Package threshold -- multisig.go implements the simple t-of-n Ed25519
// multisig scheme for the MSc phase.
//
// Design: collect t independent full Ed25519 signatures from n participants.
// Each participant signs the canonical payload independently. PartialSignature.Partial
// holds a complete Ed25519 signature (64 bytes) in this scheme.
// ThresholdAttestation.CombinedSignature is intentionally left empty; it is
// reserved for the FROST aggregation that is PhD-phase work.
package threshold

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// SimpleParticipant implements the Signer interface using a standard Ed25519 key pair.
// In the MSc simple multisig scheme, Sign produces a complete Ed25519 signature
// over the canonical payload. FROST key shares are reserved for the PhD phase.
type SimpleParticipant struct {
	id string
	kp *crypto.KeyPair
}

// NewSimpleParticipant creates a participant with the given stable ID and key pair.
func NewSimpleParticipant(id string, kp *crypto.KeyPair) *SimpleParticipant {
	return &SimpleParticipant{id: id, kp: kp}
}

// ID returns the stable identifier for this participant.
func (p *SimpleParticipant) ID() string {
	return p.id
}

// Sign produces a full Ed25519 signature over the canonical payload of the attestation.
// Despite the PartialSignature name, in the simple multisig scheme this is a complete
// signature. FROST partial shares are reserved for the PhD phase.
func (p *SimpleParticipant) Sign(a *types.Attestation) (*PartialSignature, error) {
	payload, err := crypto.CanonicalPayload(a)
	if err != nil {
		return nil, fmt.Errorf("computing canonical payload: %w", err)
	}
	sig := ed25519.Sign(p.kp.PrivateKey, payload)
	return &PartialSignature{
		ParticipantID: p.id,
		PublicKey:     []byte(p.kp.PublicKey),
		Partial:       sig,
	}, nil
}

// SimpleAggregator implements the Aggregator interface for the simple multisig scheme.
type SimpleAggregator struct{}

// Aggregate verifies that at least cfg.Threshold valid partial signatures exist,
// each from a distinct participant, and returns a combined bytes value.
// The combined value is the concatenation of (participantID|signature) pairs
// sorted by participant ID for determinism.
//
// In the PhD FROST phase, this will be replaced with proper key share aggregation
// into a single group signature.
func (SimpleAggregator) Aggregate(partials []PartialSignature, cfg ThresholdConfig) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Deduplicate by participant ID.
	seen := make(map[string]PartialSignature)
	for _, p := range partials {
		if _, exists := seen[p.ParticipantID]; !exists {
			seen[p.ParticipantID] = p
		}
	}

	if len(seen) < cfg.Threshold {
		return nil, ErrThresholdNotMet
	}

	// Collect and sort by participant ID for deterministic output.
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var combined []byte
	for _, id := range ids {
		p := seen[id]
		combined = append(combined, []byte(p.ParticipantID)...)
		combined = append(combined, p.Partial...)
	}
	return combined, nil
}

// VerifyThreshold checks that a ThresholdAttestation has at least t valid partial
// signatures, each from a distinct participant, over the canonical payload.
func VerifyThreshold(ta *ThresholdAttestation) error {
	if err := ta.Config.Validate(); err != nil {
		return err
	}

	payload, err := crypto.CanonicalPayload(&ta.Attestation)
	if err != nil {
		return fmt.Errorf("computing canonical payload: %w", err)
	}

	seen := make(map[string]struct{})
	valid := 0

	for _, ps := range ta.PartialSignatures {
		if _, dup := seen[ps.ParticipantID]; dup {
			continue
		}
		seen[ps.ParticipantID] = struct{}{}

		if len(ps.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("participant %s: invalid public key length %d", ps.ParticipantID, len(ps.PublicKey))
		}
		if len(ps.Partial) != ed25519.SignatureSize {
			return fmt.Errorf("participant %s: invalid signature length %d", ps.ParticipantID, len(ps.Partial))
		}

		pub := ed25519.PublicKey(ps.PublicKey)
		if !ed25519.Verify(pub, payload, ps.Partial) {
			return fmt.Errorf("participant %s: signature verification failed", ps.ParticipantID)
		}
		valid++
	}

	if valid < ta.Config.Threshold {
		return ErrThresholdNotMet
	}
	return nil
}

// verifyPartialSignature checks one PartialSignature against the given payload.
// This is an internal helper used by VerifyThreshold.
func verifyPartialSignature(ps PartialSignature, payload []byte) bool {
	if len(ps.PublicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(ps.Partial) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(ps.PublicKey), payload, ps.Partial)
}

// BytesEqual is a helper for tests that need to compare []byte fields.
// It is exported so test files in other packages can use it without reimporting bytes.
func BytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
