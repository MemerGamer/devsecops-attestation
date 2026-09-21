package normalize

import (
	"fmt"
	"strings"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// Severity is the canonical severity scale used across all normalizer
// adapters, ordered from least to most severe. Adapters translate each
// tool's native severity vocabulary into this scale so that findings from
// different tools can be compared and thresholded uniformly.
//
// Canonical tool mapping table (documented in detail in
// docs/severity-mapping.md, which adapter authors must follow):
//
//   - semgrep: ERROR -> high, WARNING -> medium, INFO -> low
//   - trivy: uses its own severity field directly (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN),
//     with UNKNOWN -> low
//   - checkov: a failed check maps to medium unless the tool itself supplies
//     a severity, in which case that value is parsed with ParseSeverity
//   - gitleaks: any finding -> critical (a committed secret is always critical)
//   - cargo-audit: a vulnerability with a CVSS score uses FromCVSS; otherwise
//     it maps to high. Informational warnings (unmaintained, yanked) -> low,
//     unsound -> medium
//   - sobelow: confidence High -> high, Medium -> medium, Low -> low
//   - mix_audit: advisories use FromCVSS when a CVSS score is present;
//     otherwise a reported severity string is parsed with ParseSeverity;
//     otherwise (neither present) it maps to high
//   - generic adapter: passthrough, with each severity string re-parsed
//     through ParseSeverity
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the lowercase canonical name of the severity level, which
// matches the values used by types.Severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ToTypesSeverity converts a normalize.Severity to the types.Severity used
// by the signed attestation payload.
func (s Severity) ToTypesSeverity() types.Severity {
	return types.Severity(s.String())
}

// ParseSeverity parses a severity string into the canonical scale. Parsing
// is case-insensitive. In addition to the five canonical names, a small set
// of common synonyms emitted by security tools is recognized:
//
//   - "moderate" -> medium (used by some SCA tools, e.g. npm audit style output)
//   - "warning" -> medium (generic linter/tool vocabulary)
//   - "error" -> high (generic linter/tool vocabulary; a hard failure without
//     a more specific severity is treated as high rather than critical, since
//     "critical" is reserved for the most severe findings such as secrets)
//   - "unknown" -> low (a tool that cannot determine severity should not be
//     silently ignored, but also should not be treated as inherently severe;
//     trivy uses this synonym explicitly, see the mapping table above)
//
// An unrecognized string returns an error; callers should not silently
// default to a severity level, since that could mask a real finding.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "moderate", "warning":
		return SeverityMedium, nil
	case "high", "error":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	case "unknown":
		return SeverityLow, nil
	default:
		return 0, fmt.Errorf("unrecognized severity %q", s)
	}
}

// FromCVSS maps a CVSS base score (0.0 - 10.0) to the canonical severity
// scale, following the standard CVSS v3 qualitative severity rating scale:
//
//	0.0        -> info
//	0.1 - 3.9  -> low
//	4.0 - 6.9  -> medium
//	7.0 - 8.9  -> high
//	9.0 - 10.0 -> critical
func FromCVSS(score float64) Severity {
	switch {
	case score <= 0:
		return SeverityInfo
	case score < 4:
		return SeverityLow
	case score < 7:
		return SeverityMedium
	case score < 9:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
