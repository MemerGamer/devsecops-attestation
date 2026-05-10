# DevSecOps Attestation Deploy Gate Policy
# Version: 1.0
# Required checks: sast, sca, config
# Deny conditions: missing required check, critical finding, failed check
#
# This policy is evaluated against a verified attestation chain.
# The chain must pass signature and linkage checks before this policy runs.
# All business logic lives here, not in Go, so policies are auditable and
# can be updated without recompiling the gate binary.
package devsecops.gate

import future.keywords.if
import future.keywords.in

default allow := false

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

    # No attestations signed by unauthorized signers (only checked when
    # authorized_signers is configured; absent entries are not evaluated)
    count([a |
        a := input.attestations[_]
        authorized := input.authorized_signers[a.result.check_type]
        a.signer_public_key_hex != authorized
    ]) == 0
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

deny_reasons[msg] if {
    a := input.attestations[_]
    authorized := input.authorized_signers[a.result.check_type]
    a.signer_public_key_hex != authorized
    msg := sprintf("unauthorized signer for check type %q: key does not match authorized signer", [a.result.check_type])
}
