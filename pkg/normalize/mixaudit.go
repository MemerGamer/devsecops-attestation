package normalize

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// mixAuditNormalizer translates the JSON output of `mix deps.audit --format
// json` into the canonical Result shape. See docs/severity-mapping.md for
// the severity translation this adapter follows.
type mixAuditNormalizer struct{}

func (mixAuditNormalizer) Name() string {
	return "mix-audit"
}

func (mixAuditNormalizer) CheckType() string {
	return "sca"
}

// mixAuditReport mirrors the subset of `mix deps.audit --format json`
// output this adapter consumes.
type mixAuditReport struct {
	Pass            bool                    `json:"pass"`
	Vulnerabilities []mixAuditVulnerability `json:"vulnerabilities"`
}

type mixAuditVulnerability struct {
	Advisory   mixAuditAdvisory   `json:"advisory"`
	Dependency mixAuditDependency `json:"dependency"`
}

// mixAuditAdvisory mirrors the Hex Security Working Group advisory format
// embedded in a mix_audit finding. Severity and CVSS are both optional:
// mix_audit does not guarantee either field is populated for every
// advisory.
type mixAuditAdvisory struct {
	ID                      string   `json:"id"`
	Package                 string   `json:"package"`
	Title                   string   `json:"title"`
	Description             string   `json:"description"`
	CVE                     string   `json:"cve"`
	URL                     string   `json:"url"`
	FirstPatchedVersions    []string `json:"first_patched_versions"`
	PatchedVersions         []string `json:"patched_versions"`
	VulnerableVersionRanges []string `json:"vulnerable_version_ranges"`
	Severity                string   `json:"severity"`
	CVSS                    string   `json:"cvss"`
}

type mixAuditDependency struct {
	Package  string `json:"package"`
	Version  string `json:"version"`
	Lockfile string `json:"lockfile"`
}

func (m mixAuditNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	findings, passedCount, _, err := m.normalize(r)
	return findings, passedCount, err
}

// NormalizeWithPass implements ToolPassNormalizer: mix_audit reports an
// overall "pass" boolean independently of the individual advisories, and
// Run combines it with its threshold-based verdict so a report with
// pass:false is never silently upgraded to an overall pass.
func (m mixAuditNormalizer) NormalizeWithPass(r io.Reader) ([]types.Finding, int, bool, error) {
	return m.normalize(r)
}

func (mixAuditNormalizer) normalize(r io.Reader) ([]types.Finding, int, bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, false, fmt.Errorf("reading mix_audit report: %w", err)
	}

	// mix_audit reports always carry a top-level "pass" boolean, even for a
	// clean run. Its absence means the input is not a recognized mix_audit
	// report (e.g. another tool's output fed to the wrong adapter), so this
	// is rejected rather than silently defaulting to a clean pass.
	if err := RejectCaseVariantDuplicateKeys(data); err != nil {
		return nil, 0, false, fmt.Errorf("mix_audit report: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, false, fmt.Errorf("parsing mix_audit report: %w", err)
	}
	if _, ok := raw["pass"]; !ok {
		return nil, 0, false, fmt.Errorf("mix_audit report missing required %q field, not a recognized mix_audit report", "pass")
	}

	var report mixAuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, false, fmt.Errorf("parsing mix_audit report: %w", err)
	}

	findings := make([]types.Finding, 0, len(report.Vulnerabilities))
	for _, v := range report.Vulnerabilities {
		sev, err := mixAuditSeverity(v.Advisory)
		if err != nil {
			return nil, 0, false, fmt.Errorf("advisory %q: %w", mixAuditID(v.Advisory), err)
		}

		findings = append(findings, types.Finding{
			ID:          mixAuditID(v.Advisory),
			Severity:    sev.ToTypesSeverity(),
			Title:       v.Advisory.Title,
			Description: v.Advisory.Description,
			Location:    fmt.Sprintf("%s:%s@%s", v.Dependency.Lockfile, v.Dependency.Package, v.Dependency.Version),
		})
	}

	// mix_audit reports pass as an overall boolean rather than a count of
	// checked dependencies, so there is no meaningful passed count to
	// surface here.
	return findings, 0, report.Pass, nil
}

// mixAuditID picks the finding identifier for an advisory, preferring the
// CVE identifier when present since it is the more widely recognized
// reference; it falls back to the advisory's own Hex Security Working Group
// ID otherwise.
func mixAuditID(adv mixAuditAdvisory) string {
	if adv.CVE != "" {
		return adv.CVE
	}
	return adv.ID
}

// mixAuditSeverity determines the canonical severity for an advisory,
// following docs/severity-mapping.md: an advisory with a CVSS score uses
// FromCVSS, otherwise an advisory-reported severity string is parsed with
// ParseSeverity, and an advisory with neither maps to high.
func mixAuditSeverity(adv mixAuditAdvisory) (Severity, error) {
	if adv.CVSS != "" {
		score, err := cvssBaseScore(adv.CVSS)
		if err != nil {
			return 0, fmt.Errorf("computing CVSS base score: %w", err)
		}
		return FromCVSS(score), nil
	}
	if adv.Severity != "" {
		return ParseSeverity(adv.Severity)
	}
	return SeverityHigh, nil
}

func init() {
	Register(mixAuditNormalizer{})
}
