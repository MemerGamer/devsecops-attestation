// Package crypto provides Ed25519 signing and verification for security attestations.
//
// Design decisions for PhD extensibility:
//   - Keys are represented as raw bytes, not wrapped in a specific format,
//     so they can later be embedded in X.509 certs, DID documents, or
//     distributed key material without changing the signing logic.
//   - The canonical payload function is separated from signing so that
//     threshold signing (Phase 3) can have multiple parties sign the
//     same canonical bytes independently.
//   - Digest computation is isolated so chain verification in Phase 2
//     only depends on this package, not on the full Attestation type.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// KeyPair holds an Ed25519 signing key pair.
// In Phase 3 this will be extended to support threshold key shares.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a fresh Ed25519 key pair using a secure random source.
// Each pipeline actor (runner, scanner, deployer) should have its own key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key pair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// KeyPairFromBytes reconstructs a KeyPair from raw byte slices.
// Useful for loading keys from a secrets store (GitHub Actions secrets, Vault, etc.).
func KeyPairFromBytes(pub, priv []byte) (*KeyPair, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &KeyPair{
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: ed25519.PrivateKey(priv),
	}, nil
}

// CanonicalPayload returns the canonical JSON encoding of an attestation for use
// as the signing payload. It excludes Signature and SignerPublicKey fields so
// those can be set after signing without invalidating the signature.
//
// This is the authoritative payload for both single-signer and threshold signing.
// The threshold package calls this so all participants sign the same bytes.
func CanonicalPayload(a *types.Attestation) ([]byte, error) {
	return canonicalPayload(a)
}

// canonicalPayload is the internal implementation of CanonicalPayload.
func canonicalPayload(a *types.Attestation) ([]byte, error) {
	payload := struct {
		ID             string                   `json:"id"`
		Subject        types.AttestationSubject `json:"subject"`
		Result         types.SecurityResult     `json:"result"`
		Timestamp      interface{}              `json:"timestamp"`
		PreviousDigest string                   `json:"previous_digest,omitempty"`
		SignerID       string                   `json:"signer_id,omitempty"`
	}{
		ID:             a.ID,
		Subject:        a.Subject,
		Result:         a.Result,
		Timestamp:      a.Timestamp,
		PreviousDigest: a.PreviousDigest,
		SignerID:       a.SignerID,
	}
	return json.Marshal(payload)
}

// Sign produces an Ed25519 signature over the canonical payload of the attestation
// and writes the signature and public key back into the attestation in place.
func Sign(a *types.Attestation, kp *KeyPair) error {
	payload, err := canonicalPayload(a)
	if err != nil {
		return fmt.Errorf("building canonical payload: %w", err)
	}
	a.Signature = ed25519.Sign(kp.PrivateKey, payload)
	a.SignerPublicKey = []byte(kp.PublicKey)
	return nil
}

// Verify checks that the attestation's Signature was produced by SignerPublicKey
// over the canonical payload. Returns nil on success.
//
// Note: Verify only checks cryptographic integrity. Chain integrity (that
// PreviousDigest is correct) is handled separately by the chain verifier in
// the attestation package, keeping concerns cleanly separated.
func Verify(a *types.Attestation) error {
	if len(a.SignerPublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid or missing signer public key")
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return errors.New("invalid or missing signature")
	}

	payload, err := canonicalPayload(a)
	if err != nil {
		return fmt.Errorf("building canonical payload for verification: %w", err)
	}

	pub := ed25519.PublicKey(a.SignerPublicKey)
	if !ed25519.Verify(pub, payload, a.Signature) {
		return errors.New("signature verification failed: attestation may have been tampered with")
	}
	return nil
}

// Digest computes the SHA-256 of the full attestation (including signature)
// encoded as canonical JSON. This digest is used as the PreviousDigest
// field in the next attestation, forming the chain.
func Digest(a *types.Attestation) (string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("marshalling attestation for digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
