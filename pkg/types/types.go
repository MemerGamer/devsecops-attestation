// Package types defines the core data structures for the attestation system.
// These types are intentionally serialization-friendly (JSON tags throughout)
// so attestations can be stored, transmitted, and verified across systems.
package types

import "time"

// SecurityCheckType identifies which kind of scan produced a result.
type SecurityCheckType string

const (
	CheckSAST   SecurityCheckType = "sast"
	CheckSCA    SecurityCheckType = "sca"
	CheckConfig SecurityCheckType = "config"
	CheckSecret SecurityCheckType = "secret"
)

// Severity mirrors common vulnerability severity scales.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a single issue found during a security scan.
type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"` // file:line or package@version
}

// SecurityResult is the raw output of a single security check step.
// This is what gets signed to produce an Attestation.
type SecurityResult struct {
	CheckType   SecurityCheckType `json:"check_type"`
	Tool        string            `json:"tool"`         // e.g. "semgrep", "trivy", "checkov"
	Version     string            `json:"tool_version"` // tool version for reproducibility
	TargetRef   string            `json:"target_ref"`   // git SHA or artifact digest
	RunAt       time.Time         `json:"run_at"`
	PassedCount int               `json:"passed_count"`
	Findings    []Finding         `json:"findings"`
	Passed      bool              `json:"passed"` // overall pass/fail for this check
}

// AttestationSubject identifies what the attestation is about.
type AttestationSubject struct {
	Name   string `json:"name"`   // e.g. "myapp"
	Digest string `json:"digest"` // SHA-256 of the artifact or commit
}

// Attestation is a signed, optionally chained security result.
//
// Chain integrity: each attestation may reference the digest of the
// previous attestation in the pipeline, forming a tamper-evident chain.
// The Verifier checks that this chain is unbroken before the deploy gate.
//
// PhD extension note: the chain structure maps naturally to a distributed
// DAG where multiple nodes can produce and gossip attestations; threshold
// signatures (Phase 3) extend the SignerPublicKey field to a set.
type Attestation struct {
	// Identity
	ID      string             `json:"id"`      // random UUID
	Subject AttestationSubject `json:"subject"` // what is being attested

	// Payload (the thing that is signed)
	Result    SecurityResult `json:"result"`
	Timestamp time.Time      `json:"timestamp"`

	// Chain linkage (Phase 2)
	// PreviousDigest is the SHA-256 hex of the previous Attestation's canonical
	// JSON. Empty string for the first attestation in a pipeline run.
	PreviousDigest string `json:"previous_digest,omitempty"`

	// Cryptographic proof (Phase 1)
	SignerPublicKey []byte `json:"signer_public_key"` // Ed25519 public key (raw 32 bytes)
	Signature       []byte `json:"signature"`          // Ed25519 signature over canonical payload

	// Transparency log reference (optional, set after submission)
	LogEntry string `json:"log_entry,omitempty"` // e.g. Rekor UUID
}

// PolicyInput is the structure passed to the OPA policy engine.
// It collects the full verified chain so the policy can reason about
// the complete set of checks that ran before a deployment.
type PolicyInput struct {
	Subject      AttestationSubject `json:"subject"`
	Attestations []Attestation      `json:"attestations"`
	RunAt        time.Time          `json:"run_at"`
}

// GateDecision is the output of the deploy gate evaluation.
type GateDecision struct {
	Allow   bool     `json:"allow"`
	Reasons []string `json:"reasons"` // human-readable explanation
}
