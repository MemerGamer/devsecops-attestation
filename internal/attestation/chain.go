// Package attestation handles building and verifying chains of signed attestations.
//
// A chain ties together all the security checks that ran in a single pipeline
// execution. Each link references the digest of the previous one, so any
// tampering (inserting, removing, or reordering steps) is detectable.
//
// PhD extension: the Chain type maps cleanly to a distributed DAG.
// Replace the slice with a directed graph and you have the foundation
// for multi-node attestation propagation over a network.
package attestation

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// Chain holds an ordered sequence of attestations for a single pipeline run.
type Chain struct {
	attestations []types.Attestation
}

// NewChain creates an empty chain.
func NewChain() *Chain {
	return &Chain{}
}

// NewChainFromSlice creates a Chain pre-populated with already-signed attestations.
// Used by the CLI sign command to continue building an existing chain.
// Attestations are not re-signed or re-verified here; that is the caller's responsibility.
func NewChainFromSlice(attestations []types.Attestation) *Chain {
	out := make([]types.Attestation, len(attestations))
	copy(out, attestations)
	return &Chain{attestations: out}
}

// Add signs a SecurityResult with the given key pair and appends it to the chain.
// It automatically links the new attestation to the previous one via PreviousDigest.
func (c *Chain) Add(
	subject types.AttestationSubject,
	result types.SecurityResult,
	kp *crypto.KeyPair,
) (*types.Attestation, error) {
	a := &types.Attestation{
		ID:        uuid.New().String(),
		Subject:   subject,
		Result:    result,
		Timestamp: time.Now().UTC(),
	}

	// Link to previous attestation if the chain is not empty.
	if len(c.attestations) > 0 {
		prev := &c.attestations[len(c.attestations)-1]
		digest, err := crypto.Digest(prev)
		if err != nil {
			return nil, fmt.Errorf("computing previous digest: %w", err)
		}
		a.PreviousDigest = digest
	}

	if err := crypto.Sign(a, kp); err != nil {
		return nil, fmt.Errorf("signing attestation: %w", err)
	}

	c.attestations = append(c.attestations, *a)
	return a, nil
}

// Attestations returns a copy of the chain's attestations slice.
func (c *Chain) Attestations() []types.Attestation {
	out := make([]types.Attestation, len(c.attestations))
	copy(out, c.attestations)
	return out
}

// VerificationResult captures the outcome of verifying a single attestation.
type VerificationResult struct {
	AttestationID  string
	CheckType      string
	SignatureValid bool
	ChainValid     bool
	Error          error
}

// VerifyChain verifies every attestation in the slice:
//  1. Ed25519 signature integrity (crypto.Verify)
//  2. Chain linkage -- each attestation's PreviousDigest matches the
//     actual digest of the preceding attestation
//
// It returns a result per attestation so callers can report granular failures,
// and a top-level error if the overall chain is broken.
func VerifyChain(attestations []types.Attestation) ([]VerificationResult, error) {
	if len(attestations) == 0 {
		return nil, errors.New("empty attestation chain")
	}

	results := make([]VerificationResult, len(attestations))
	var chainErr error

	for i, a := range attestations {
		r := VerificationResult{
			AttestationID: a.ID,
			CheckType:     string(a.Result.CheckType),
		}

		// 1. Verify signature.
		if err := crypto.Verify(&attestations[i]); err != nil {
			r.SignatureValid = false
			r.Error = fmt.Errorf("signature check failed: %w", err)
			chainErr = r.Error
		} else {
			r.SignatureValid = true
		}

		// 2. Verify chain linkage.
		if i == 0 {
			// First attestation must have no previous digest.
			if a.PreviousDigest != "" {
				r.ChainValid = false
				r.Error = errors.New("first attestation must not have a previous digest")
				chainErr = r.Error
			} else {
				r.ChainValid = true
			}
		} else {
			prev := &attestations[i-1]
			expectedDigest, err := crypto.Digest(prev)
			if err != nil {
				r.ChainValid = false
				r.Error = fmt.Errorf("computing expected previous digest: %w", err)
				chainErr = r.Error
			} else if a.PreviousDigest != expectedDigest {
				r.ChainValid = false
				r.Error = fmt.Errorf(
					"chain broken at position %d: expected digest %s, got %s",
					i, expectedDigest[:12]+"...", a.PreviousDigest[:12]+"...",
				)
				chainErr = r.Error
			} else {
				r.ChainValid = true
			}
		}

		results[i] = r
	}

	return results, chainErr
}
