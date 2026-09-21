# DevSecOps Attestation Deploy Gate Policy
# Version: 2.1
#
# Canonical, parameterizable deploy gate policy. This is the single source of
# truth for the default gate policy: internal/policy embeds this file and the
# CI pipeline references it directly, so there is exactly one copy to audit.
#
# Default semantics (used when no data.config overrides are supplied):
#   - Required checks: sast, sca, config, secret
#   - Blocking severity threshold: high (findings at or above this
#     severity block deployment)
#   - Zero-tolerance check types: secret (any finding of any severity on
#     these check types blocks deployment, regardless of fail_on_severity)
#   - No attestation with result.passed == false
#   - signer_public_key_hex must match input.authorized_signers[check_type]
#     when an entry is configured for that check type
#
# Parameterization (all optional, read from the OPA data document):
#   data.config.required_checks       -- array of required check_type strings
#   data.config.fail_on_severity      -- one of info, low, medium, high, critical
#   data.config.zero_tolerance_checks -- array of check_type strings
#
# Fail-closed guarantees:
#   - A malformed data.config (an unrecognized fail_on_severity, or a
#     required_checks / zero_tolerance_checks value that is not a non-empty
#     array of strings) never produces a silent allow. config_valid captures
#     this and allow requires it; deny_reasons names the specific problem.
#     blocking_threshold always resolves to a defined value (falling back to
#     the "critical" rank) so an invalid fail_on_severity cannot make the
#     severity comparison undefined and skip every finding.
#   - A finding whose severity is not a key of severity_rank (a typo, an
#     unrecognized scale, an empty string) is never silently ignored: it is
#     collected in unrecognized_severity_findings and always blocks
#     deployment, independent of fail_on_severity.
#
# This policy is evaluated against a verified attestation chain. The chain
# must pass signature and linkage checks (and signer authorization) before
# this policy runs. All business logic lives here, not in Go, so policies
# are auditable and can be updated without recompiling the gate binary.
package devsecops.gate

import rego.v1

default allow := false

# Total ordering used to compare finding severities against the configured
# blocking threshold.
severity_rank := {
	"info": 0,
	"low": 1,
	"medium": 2,
	"high": 3,
	"critical": 4,
}

# valid_severities lists the accepted fail_on_severity values, in the order
# used for the human-readable deny reason.
valid_severities := ["info", "low", "medium", "high", "critical"]

# fail_on_severity_ok is true when data.config.fail_on_severity is absent, or
# present and a recognized key of severity_rank. A value that is present but
# unrecognized (wrong type, misspelled, empty string) is rejected rather than
# silently accepted.
fail_on_severity_ok if {
	not data.config.fail_on_severity
}

fail_on_severity_ok if {
	severity_rank[data.config.fail_on_severity]
}

# required_checks_ok and zero_tolerance_checks_ok are true when the
# corresponding data.config key is absent, or present as a non-empty array
# of strings. A present-but-malformed value (a string instead of an array,
# an empty array) is rejected rather than silently treated as "no checks
# required" / "no zero tolerance".
required_checks_ok if {
	not data.config.required_checks
}

required_checks_ok if {
	is_array(data.config.required_checks)
	count(data.config.required_checks) > 0
	every c in data.config.required_checks {
		is_string(c)
	}
}

zero_tolerance_checks_ok if {
	not data.config.zero_tolerance_checks
}

zero_tolerance_checks_ok if {
	is_array(data.config.zero_tolerance_checks)
	count(data.config.zero_tolerance_checks) > 0
	every c in data.config.zero_tolerance_checks {
		is_string(c)
	}
}

# config_valid is true only when every data.config override that was
# supplied is well-formed. allow requires config_valid so a malformed
# override always denies instead of silently loosening the policy.
config_valid if {
	fail_on_severity_ok
	required_checks_ok
	zero_tolerance_checks_ok
}

# required_checks is the set of check_type values that must appear in the
# attestation chain. Falls back to {"sast", "sca", "config", "secret"} when
# data.config.required_checks is absent or fails required_checks_ok.
default required_checks := {"sast", "sca", "config", "secret"}

required_checks := {c | some c in data.config.required_checks} if {
	required_checks_ok
	data.config.required_checks
}

# fail_on_severity is the minimum severity (inclusive) that blocks
# deployment. Falls back to "high" when data.config.fail_on_severity is
# absent. This mirrors the raw override value (even when invalid) so
# deny_reasons can report exactly what was configured; blocking_threshold
# below is the fail-closed value actually used for comparisons.
default fail_on_severity := "high"

fail_on_severity := data.config.fail_on_severity if {
	data.config.fail_on_severity
}

# zero_tolerance_checks is the set of check_type values for which any
# finding, regardless of severity, blocks deployment. Falls back to
# {"secret"} when data.config.zero_tolerance_checks is absent or fails
# zero_tolerance_checks_ok.
default zero_tolerance_checks := {"secret"}

zero_tolerance_checks := {c | some c in data.config.zero_tolerance_checks} if {
	zero_tolerance_checks_ok
	data.config.zero_tolerance_checks
}

ran_checks := {r.result.check_type | some r in input.attestations}

# blocking_threshold always resolves to a defined severity rank, even when
# fail_on_severity is invalid, so the severity comparison below is never
# undefined (and therefore never silently skipped). It falls back to the
# "critical" rank whenever fail_on_severity_ok is false; config_valid is
# still what causes the overall deny in that case.
blocking_threshold := severity_rank[fail_on_severity] if {
	fail_on_severity_ok
}

default blocking_threshold := 4

# blocking_findings are findings at or above the configured severity
# threshold, on any check type. Only findings with a recognized severity are
# considered here; unrecognized severities are handled separately below so
# they cannot be silently excluded from both checks.
blocking_findings := [f |
	some a in input.attestations
	some f in a.result.findings
	severity_rank[f.severity] >= blocking_threshold
]

# unrecognized_severity_findings are findings whose severity is not a key of
# severity_rank at all (a typo, an unsupported scale, an empty string).
# These always block deployment: an unrecognized severity must never be
# silently treated as passing.
unrecognized_severity_findings := [f |
	some a in input.attestations
	some f in a.result.findings
	not severity_rank[f.severity]
]

# zero_tolerance_findings are findings of any severity on a check type
# configured for zero tolerance.
zero_tolerance_findings := [f |
	some a in input.attestations
	a.result.check_type in zero_tolerance_checks
	some f in a.result.findings
]

# unauthorized_attestations are attestations whose signer does not match the
# configured authorized signer for their check type. Check types without a
# configured entry in input.authorized_signers are not evaluated.
unauthorized_attestations := [a |
	some a in input.attestations
	authorized := input.authorized_signers[a.result.check_type]
	a.signer_public_key_hex != authorized
]

allow if {
	# The supplied data.config overrides (if any) are well-formed.
	config_valid

	# All required checks ran
	missing := required_checks - ran_checks
	count(missing) == 0

	# No findings at or above the blocking severity threshold
	count(blocking_findings) == 0

	# No findings with an unrecognized severity
	count(unrecognized_severity_findings) == 0

	# No findings on zero-tolerance check types, regardless of severity
	count(zero_tolerance_findings) == 0

	# All checks passed
	failed := [a | some a in input.attestations; a.result.passed == false]
	count(failed) == 0

	# No attestations signed by unauthorized signers
	count(unauthorized_attestations) == 0
}

# Collect reasons for denial (useful for human-readable output)
deny_reasons contains msg if {
	not fail_on_severity_ok
	msg := sprintf("invalid data.config.fail_on_severity %v: must be one of %v", [data.config.fail_on_severity, valid_severities])
}

deny_reasons contains msg if {
	not required_checks_ok
	msg := sprintf("invalid data.config.required_checks %v: must be a non-empty array of strings", [data.config.required_checks])
}

deny_reasons contains msg if {
	not zero_tolerance_checks_ok
	msg := sprintf("invalid data.config.zero_tolerance_checks %v: must be a non-empty array of strings", [data.config.zero_tolerance_checks])
}

deny_reasons contains msg if {
	missing := required_checks - ran_checks
	count(missing) > 0
	msg := sprintf("missing required checks: %v", [missing])
}

# Preserve the original "critical finding(s)" wording when the blocking
# threshold is explicitly configured to the "critical" severity (no longer
# the default, but still a supported value).
deny_reasons contains msg if {
	fail_on_severity_ok
	fail_on_severity == "critical"
	count(blocking_findings) > 0
	msg := sprintf("found %d critical finding(s)", [count(blocking_findings)])
}

deny_reasons contains msg if {
	fail_on_severity_ok
	fail_on_severity != "critical"
	count(blocking_findings) > 0
	msg := sprintf("found %d finding(s) at or above %q severity", [count(blocking_findings), fail_on_severity])
}

# When fail_on_severity itself is invalid, blocking_threshold has already
# fallen back to the critical rank (see above); report that plainly instead
# of formatting the invalid raw value into the message.
deny_reasons contains msg if {
	not fail_on_severity_ok
	count(blocking_findings) > 0
	msg := sprintf("found %d finding(s) at or above the critical severity threshold (fallback applied because data.config.fail_on_severity is invalid)", [count(blocking_findings)])
}

deny_reasons contains msg if {
	count(unrecognized_severity_findings) > 0
	msg := sprintf("found %d finding(s) with unrecognized severity", [count(unrecognized_severity_findings)])
}

# Preserve the original "hardcoded credential finding(s)" wording when the
# zero-tolerance set is the default {"secret"}.
deny_reasons contains msg if {
	zero_tolerance_checks == {"secret"}
	count(zero_tolerance_findings) > 0
	msg := sprintf("found %d hardcoded credential finding(s)", [count(zero_tolerance_findings)])
}

deny_reasons contains msg if {
	zero_tolerance_checks != {"secret"}
	count(zero_tolerance_findings) > 0
	msg := sprintf("found %d zero-tolerance finding(s) for check type(s) %v", [count(zero_tolerance_findings), zero_tolerance_checks])
}

deny_reasons contains msg if {
	failed := [a.result.check_type | some a in input.attestations; a.result.passed == false]
	count(failed) > 0
	msg := sprintf("failed checks: %v", [failed])
}

deny_reasons contains msg if {
	some a in unauthorized_attestations
	msg := sprintf("unauthorized signer for check type %q: key does not match authorized signer", [a.result.check_type])
}
