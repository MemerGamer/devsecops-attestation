// Package policy evaluates a set of verified attestations against an OPA policy
// to produce a deploy gate decision (allow / block).
//
// The policy engine is intentionally thin: it marshals the attestation chain
// into the PolicyInput structure and hands it to OPA. All business logic
// lives in the Rego policy file, not in Go. This makes policies auditable,
// version-controlled, and changeable without recompiling the gate binary.
package policy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
	"github.com/MemerGamer/devsecops-attestation/policies"
)

// DefaultPolicy is the canonical, parameterizable deploy gate policy.
// It is the single source of truth: policies/deploy.rego at the repository
// root, embedded at build time so the gate binary carries a working policy
// without any external file. Other repositories that vendor this module
// reuse this policy, or point --policy at their own copy of the same file.
var DefaultPolicy = policies.Deploy

// Evaluator wraps an OPA query for deployment gate decisions.
type Evaluator struct {
	policy string         // Rego source
	data   map[string]any // optional data.config document
}

// EvaluatorOption configures an Evaluator at construction time.
type EvaluatorOption func(*Evaluator)

// WithData sets the object loaded into the OPA data document under "config".
// Policies read parameters such as required_checks, fail_on_severity, and
// zero_tolerance_checks from data.config; passing nil (or omitting this
// option) leaves data.config undefined so the policy's own defaults apply.
func WithData(data map[string]any) EvaluatorOption {
	return func(e *Evaluator) {
		e.data = data
	}
}

// NewEvaluator creates an Evaluator using the provided Rego policy source.
// Pass an empty string to use the built-in DefaultPolicy.
func NewEvaluator(policySource string, opts ...EvaluatorOption) *Evaluator {
	if policySource == "" {
		policySource = DefaultPolicy
	}
	e := &Evaluator{policy: policySource}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// EvaluateFromFile loads a Rego policy from policyPath before evaluating.
// Pass an empty string to use DefaultPolicy.
func EvaluateFromFile(ctx context.Context, policyPath string, input types.PolicyInput, opts ...EvaluatorOption) (*types.GateDecision, error) {
	policySource := ""
	if policyPath != "" {
		b, err := os.ReadFile(policyPath)
		if err != nil {
			return nil, fmt.Errorf("reading policy file %s: %w", policyPath, err)
		}
		policySource = string(b)
	}
	return NewEvaluator(policySource, opts...).Evaluate(ctx, input)
}

// Evaluate runs the policy against the provided attestation chain.
// The attestations must already be verified (signatures + chain) before calling this.
func (e *Evaluator) Evaluate(ctx context.Context, input types.PolicyInput) (*types.GateDecision, error) {
	// Build the OPA query. When e.data is set, it is loaded into the OPA
	// store under "config" so the policy can read data.config.* overrides.
	regoOpts := []func(*rego.Rego){
		rego.Module("policy.rego", e.policy),
		rego.Input(toMap(input)),
	}
	if e.data != nil {
		store := inmem.NewFromObject(map[string]any{"config": e.data})
		regoOpts = append(regoOpts, rego.Store(store))
	}

	allowQuery := rego.New(append([]func(*rego.Rego){rego.Query("data.devsecops.gate.allow")}, regoOpts...)...)
	denyQuery := rego.New(append([]func(*rego.Rego){rego.Query("data.devsecops.gate.deny_reasons")}, regoOpts...)...)

	// Evaluate allow.
	allowRS, err := allowQuery.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating allow policy: %w", err)
	}
	allow := false
	if len(allowRS) > 0 && len(allowRS[0].Expressions) > 0 {
		allow, _ = allowRS[0].Expressions[0].Value.(bool)
	}

	// Evaluate deny reasons.
	denyRS, err := denyQuery.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluating deny_reasons policy: %w", err)
	}
	var reasons []string
	if len(denyRS) > 0 && len(denyRS[0].Expressions) > 0 {
		v := denyRS[0].Expressions[0].Value
		switch set := v.(type) {
		case map[string]interface{}:
			// OPA with future.keywords syntax: set elements are map keys
			for k := range set {
				reasons = append(reasons, k)
			}
		case []interface{}:
			// OPA with import rego.v1 syntax: set is serialized as array
			for _, elem := range set {
				if s, ok := elem.(string); ok {
					reasons = append(reasons, s)
				}
			}
		}
	}
	if allow && len(reasons) == 0 {
		reasons = []string{"all checks passed"}
	}

	return &types.GateDecision{
		Allow:   allow,
		Reasons: reasons,
	}, nil
}

// toMap converts a PolicyInput to a map[string]interface{} for OPA.
// OPA's rego.Input expects a plain Go map, not a typed struct.
// It also adds a signer_public_key_hex field to each attestation so Rego
// rules can compare signer identity using the hex format produced by keygen.
func toMap(input types.PolicyInput) map[string]interface{} {
	b, _ := json.Marshal(input)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)

	// Inject signer_public_key_hex into each attestation map. json.Marshal
	// encodes []byte as base64; convert it to the hex format that authorized_signers uses.
	if atts, ok := m["attestations"].([]interface{}); ok {
		for _, elem := range atts {
			if att, ok := elem.(map[string]interface{}); ok {
				if b64, ok := att["signer_public_key"].(string); ok {
					raw, err := base64.StdEncoding.DecodeString(b64)
					if err == nil {
						att["signer_public_key_hex"] = hex.EncodeToString(raw)
					}
				}
			}
		}
	}
	return m
}
