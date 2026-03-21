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
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// DefaultPolicy is a starter Rego policy.
// In production, load this from a file or a policy server.
const DefaultPolicy = `
package devsecops.gate

import future.keywords.if
import future.keywords.in

default allow := false

# Allow deployment only when ALL of the following are true:
#   1. All required check types were run
#   2. No critical findings exist
#   3. All checks passed

required_checks := {"sast", "sca", "config"}

ran_checks := {r.result.check_type | r := input.attestations[_]}

allow if {
    # All required checks ran
    missing := required_checks - ran_checks
    count(missing) == 0

    # No critical findings
    count([f |
        a := input.attestations[_]
        f := a.result.findings[_]
        f.severity == "critical"
    ]) == 0

    # All checks passed
    failed := [a | a := input.attestations[_]; a.result.passed == false]
    count(failed) == 0
}

# Collect reasons for denial (useful for human-readable output)
deny_reasons[msg] if {
    missing := required_checks - ran_checks
    count(missing) > 0
    msg := sprintf("missing required checks: %v", [missing])
}

deny_reasons[msg] if {
    findings := [f |
        a := input.attestations[_]
        f := a.result.findings[_]
        f.severity == "critical"
    ]
    count(findings) > 0
    msg := sprintf("found %d critical finding(s)", [count(findings)])
}

deny_reasons[msg] if {
    failed := [a.result.check_type | a := input.attestations[_]; a.result.passed == false]
    count(failed) > 0
    msg := sprintf("failed checks: %v", [failed])
}
`

// Evaluator wraps an OPA query for deployment gate decisions.
type Evaluator struct {
	policy string // Rego source
}

// NewEvaluator creates an Evaluator using the provided Rego policy source.
// Pass an empty string to use the built-in DefaultPolicy.
func NewEvaluator(policySource string) *Evaluator {
	if policySource == "" {
		policySource = DefaultPolicy
	}
	return &Evaluator{policy: policySource}
}

// EvaluateFromFile loads a Rego policy from policyPath before evaluating.
// Pass an empty string to use DefaultPolicy.
func EvaluateFromFile(ctx context.Context, policyPath string, input types.PolicyInput) (*types.GateDecision, error) {
	policySource := ""
	if policyPath != "" {
		b, err := os.ReadFile(policyPath)
		if err != nil {
			return nil, fmt.Errorf("reading policy file %s: %w", policyPath, err)
		}
		policySource = string(b)
	}
	return NewEvaluator(policySource).Evaluate(ctx, input)
}

// Evaluate runs the policy against the provided attestation chain.
// The attestations must already be verified (signatures + chain) before calling this.
func (e *Evaluator) Evaluate(ctx context.Context, input types.PolicyInput) (*types.GateDecision, error) {
	// Build the OPA query.
	allowQuery := rego.New(
		rego.Query("data.devsecops.gate.allow"),
		rego.Module("policy.rego", e.policy),
		rego.Input(toMap(input)),
	)
	denyQuery := rego.New(
		rego.Query("data.devsecops.gate.deny_reasons"),
		rego.Module("policy.rego", e.policy),
		rego.Input(toMap(input)),
	)

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
		if set, ok := denyRS[0].Expressions[0].Value.(map[string]interface{}); ok {
			for k := range set {
				reasons = append(reasons, k)
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
func toMap(input types.PolicyInput) map[string]interface{} {
	b, _ := json.Marshal(input)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}
