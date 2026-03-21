// Package threshold implements multi-party threshold signing for attestations.
//
// Status: Phase 3 skeleton -- interfaces are defined, crypto is stubbed.
// This package is intentionally left incomplete for the PhD extension.
//
// Design intent:
//
//	A t-of-n threshold scheme requires t out of n designated signers
//	to co-sign an attestation before it is considered valid. This is
//	particularly useful in scenarios where:
//	  - No single CI runner should be trusted alone (compromised runner attack)
//	  - Multiple independent security teams must approve a deployment
//	  - A network of nodes must reach a signing quorum (PhD: BFT context)
//
// Recommended approach for implementation:
//
//	Use FROST (Flexible Round-Optimized Schnorr Threshold) or a simpler
//	t-of-n Ed25519 multisig scheme. The golang.org/x/crypto package provides
//	the Ed25519 primitives; FROST requires additional libraries or a
//	custom implementation (good PhD contribution territory).
//
// PhD extension path:
//
//	Replace the in-process ParticipantSet with network peers.
//	The GossipProtocol interface below is a placeholder for the network
//	layer that will be the focus of the PhD: peer discovery, partial
//	signature propagation, aggregation, and Byzantine fault tolerance.
package threshold

import (
	"errors"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// PartialSignature holds a single participant's contribution to a threshold signature.
type PartialSignature struct {
	ParticipantID string
	PublicKey     []byte
	Partial       []byte // partial signature bytes -- scheme-dependent
}

// ThresholdConfig defines the t-of-n parameters.
type ThresholdConfig struct {
	Threshold    int // t -- minimum signers required
	Participants int // n -- total signers in the group
}

// Validate checks that the config makes mathematical sense.
func (c ThresholdConfig) Validate() error {
	if c.Threshold < 1 {
		return errors.New("threshold must be at least 1")
	}
	if c.Participants < c.Threshold {
		return errors.New("participants must be >= threshold")
	}
	return nil
}

// Signer is the interface a threshold participant must implement.
// Each participant holds a private key share and can produce a partial signature.
//
// In the MSc prototype: implement with a simple map of Ed25519 keys where
// the "aggregation" is just verifying t independent full signatures.
// In the PhD: replace with FROST key shares and the proper aggregation protocol.
type Signer interface {
	// ID returns a stable identifier for this participant (e.g. "runner-1", "security-team").
	ID() string
	// Sign produces a partial signature over the canonical attestation payload.
	Sign(a *types.Attestation) (*PartialSignature, error)
}

// Aggregator combines partial signatures from t-of-n participants into a
// single verifiable combined signature.
//
// TODO(phase6): implement this.
// Simple MSc version: collect t full Ed25519 sigs, store all of them.
// PhD version: implement FROST aggregation into a single group signature.
type Aggregator interface {
	Aggregate(partials []PartialSignature, cfg ThresholdConfig) ([]byte, error)
}

// GossipProtocol is a placeholder interface for the PhD network layer.
// It represents the mechanism by which partial signatures are propagated
// between signing nodes before aggregation.
//
// TODO(phd): implement over TCP/UDP with peer discovery, retransmission,
// and Byzantine fault detection.
type GossipProtocol interface {
	// Broadcast sends a partial signature to all known peers.
	Broadcast(partial *PartialSignature) error
	// Collect gathers partial signatures from peers until threshold is reached
	// or timeout occurs.
	Collect(cfg ThresholdConfig) ([]PartialSignature, error)
}

// ThresholdAttestation extends the base Attestation with multi-party signing data.
// This replaces the single SignerPublicKey + Signature fields for Phase 3.
type ThresholdAttestation struct {
	types.Attestation
	Config            ThresholdConfig    `json:"threshold_config"`
	PartialSignatures []PartialSignature `json:"partial_signatures"`
	CombinedSignature []byte             `json:"combined_signature,omitempty"`
}

// ErrThresholdNotMet is returned when fewer than t partial signatures are available.
var ErrThresholdNotMet = errors.New("threshold not met: insufficient partial signatures")

// Verify checks that a ThresholdAttestation has at least t valid partial signatures.
//
// TODO(phase6): implement actual partial signature verification.
// For now this is a placeholder that checks the count only.
func Verify(ta *ThresholdAttestation) error {
	if err := ta.Config.Validate(); err != nil {
		return err
	}
	if len(ta.PartialSignatures) < ta.Config.Threshold {
		return ErrThresholdNotMet
	}
	// TODO(phase6): verify each PartialSignature against its corresponding public key share.
	// TODO(phase6): if CombinedSignature is set, verify it against the group public key.
	return nil
}
