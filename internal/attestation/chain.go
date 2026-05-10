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
	attestations  []types.Attestation
	nextSignerID  string
	nextLogEntry  string
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
	signerID := c.nextSignerID
	c.nextSignerID = ""
	logEntry := c.nextLogEntry
	c.nextLogEntry = ""

	a := &types.Attestation{
		ID:        uuid.New().String(),
		Subject:   subject,
		Result:    result,
		Timestamp: time.Now().UTC(),
		SignerID:  signerID,
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

	// LogEntry is set after signing: it is a transparency log reference and
	// is intentionally excluded from the canonical payload (and signature).
	a.LogEntry = logEntry

	c.attestations = append(c.attestations, *a)
	return a, nil
}

// SetNextSignerID sets the human-readable signer identity that will be embedded
// in the next attestation created by Add. The value is included in the canonical
// payload (and therefore covered by the Ed25519 signature), then reset to ""
// so subsequent Add calls are unaffected unless SetNextSignerID is called again.
func (c *Chain) SetNextSignerID(id string) {
	c.nextSignerID = id
}

// SetNextLogEntry sets a transparency log reference that will be attached to
// the next attestation created by Add. The value is stored in LogEntry after
// signing (it is not in the canonical payload), then reset to "" so subsequent
// Add calls are unaffected unless SetNextLogEntry is called again.
func (c *Chain) SetNextLogEntry(entry string) {
	c.nextLogEntry = entry
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

// VerifyOptions configures optional checks applied by VerifyChainWithOptions
// on top of the always-on signature and chain-linkage verification.
type VerifyOptions struct {
	// MaxAge is the maximum allowed age of any attestation relative to Now.
	// Zero means no maximum age check is applied.
	MaxAge time.Duration
	// ClockSkewTolerance is the allowance added to Now when detecting future
	// timestamps. Zero uses a default of 60 seconds.
	ClockSkewTolerance time.Duration
	// Now is the reference time used for age and future-timestamp checks.
	// Zero means time.Now() is used at the point of verification.
	Now time.Time
}

func (o VerifyOptions) referenceTime() time.Time {
	if o.Now.IsZero() {
		return time.Now().UTC()
	}
	return o.Now
}

func (o VerifyOptions) clockSkew() time.Duration {
	if o.ClockSkewTolerance == 0 {
		return 60 * time.Second
	}
	return o.ClockSkewTolerance
}

// VerifyChain verifies every attestation using default options.
// It is equivalent to calling VerifyChainWithOptions with a zero VerifyOptions.
func VerifyChain(attestations []types.Attestation) ([]VerificationResult, error) {
	return VerifyChainWithOptions(attestations, VerifyOptions{})
}

// VerifyChainWithOptions verifies every attestation in the slice.
// Checks performed, in order, per attestation:
//  1. Ed25519 signature integrity (crypto.Verify)
//  2. Chain linkage: each PreviousDigest matches the actual digest of the preceding attestation
//  3. Subject consistency: all attestations share the subject of the first
//  4. No future timestamps (within ClockSkewTolerance, default 60 s)
//  5. Monotonically non-decreasing timestamps along the chain
//  6. Maximum attestation age (only when opts.MaxAge > 0)
//  7. No duplicate check types within the chain
//
// It returns a result per attestation so callers can report granular failures,
// and a top-level error if any check fails.
func VerifyChainWithOptions(attestations []types.Attestation, opts VerifyOptions) ([]VerificationResult, error) {
	if len(attestations) == 0 {
		return nil, errors.New("empty attestation chain")
	}

	results := make([]VerificationResult, len(attestations))
	var chainErr error

	now := opts.referenceTime()
	skew := opts.clockSkew()
	firstSubject := attestations[0].Subject
	seenCheckTypes := make(map[types.SecurityCheckType]int)

	for i := range attestations {
		a := &attestations[i]
		r := VerificationResult{
			AttestationID: a.ID,
			CheckType:     string(a.Result.CheckType),
			ChainValid:    true,
		}

		// recordChainErr marks chain validity false and propagates the error.
		// The first chain error for this attestation is preserved in r.Error;
		// every call updates chainErr so the caller sees the last failure.
		recordChainErr := func(err error) {
			r.ChainValid = false
			if r.Error == nil {
				r.Error = err
			}
			chainErr = err
		}

		// 1. Verify Ed25519 signature.
		if err := crypto.Verify(a); err != nil {
			r.SignatureValid = false
			r.Error = fmt.Errorf("signature check failed: %w", err)
			chainErr = r.Error
		} else {
			r.SignatureValid = true
		}

		// 2. Verify chain linkage.
		if i == 0 {
			if a.PreviousDigest != "" {
				recordChainErr(errors.New("first attestation must not have a previous digest"))
			}
		} else {
			prev := &attestations[i-1]
			expectedDigest, err := crypto.Digest(prev)
			if err != nil {
				recordChainErr(fmt.Errorf("computing expected previous digest: %w", err))
			} else if a.PreviousDigest != expectedDigest {
				got, exp := a.PreviousDigest, expectedDigest
				if len(got) > 12 {
					got = got[:12] + "..."
				}
				if len(exp) > 12 {
					exp = exp[:12] + "..."
				}
				recordChainErr(fmt.Errorf(
					"chain broken at position %d: expected digest %s, got %q",
					i, exp, got,
				))
			}
		}

		// 3. Subject consistency: all attestations must share the first attestation's subject.
		if i > 0 && (a.Subject.Name != firstSubject.Name || a.Subject.Digest != firstSubject.Digest) {
			recordChainErr(fmt.Errorf(
				"subject mismatch at position %d: got {name:%q digest:%q}, want {name:%q digest:%q}",
				i, a.Subject.Name, a.Subject.Digest, firstSubject.Name, firstSubject.Digest,
			))
		}

		// 4. No future timestamps (beyond clock skew tolerance).
		if a.Timestamp.After(now.Add(skew)) {
			recordChainErr(fmt.Errorf(
				"attestation %d timestamp %v is in the future (reference %v, tolerance %v)",
				i, a.Timestamp.UTC(), now, skew,
			))
		}

		// 5. Timestamps must be monotonically non-decreasing.
		if i > 0 && a.Timestamp.Before(attestations[i-1].Timestamp) {
			recordChainErr(fmt.Errorf(
				"timestamp regression at position %d: %v precedes position %d's %v",
				i, a.Timestamp.UTC(), i-1, attestations[i-1].Timestamp.UTC(),
			))
		}

		// 6. Maximum attestation age (optional).
		if opts.MaxAge > 0 && now.Sub(a.Timestamp) > opts.MaxAge {
			recordChainErr(fmt.Errorf(
				"attestation %d is too old: age %v exceeds maximum %v",
				i, now.Sub(a.Timestamp).Truncate(time.Second), opts.MaxAge,
			))
		}

		// 7. No duplicate check types.
		if prev, ok := seenCheckTypes[a.Result.CheckType]; ok {
			recordChainErr(fmt.Errorf(
				"duplicate check type %q at positions %d and %d",
				a.Result.CheckType, prev, i,
			))
		} else {
			seenCheckTypes[a.Result.CheckType] = i
		}

		results[i] = r
	}

	return results, chainErr
}
