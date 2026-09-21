package normalize

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// cargoAuditNormalizer translates the JSON output of `cargo audit --json`
// (the RustSec advisory database scanner) into the canonical Result shape.
//
// cargo audit reports two kinds of entries: vulnerabilities (advisories that
// match a locked dependency exactly) and warnings (unmaintained, yanked, or
// unsound crates, which are informational rather than exploitable). Both are
// surfaced as findings; see docs/severity-mapping.md for the severity rules.
type cargoAuditNormalizer struct{}

func (cargoAuditNormalizer) Name() string {
	return "cargo-audit"
}

func (cargoAuditNormalizer) CheckType() string {
	return "sca"
}

type cargoAuditReport struct {
	Lockfile struct {
		DependencyCount int `json:"dependency-count"`
	} `json:"lockfile"`
	Vulnerabilities struct {
		Found bool                  `json:"found"`
		Count int                   `json:"count"`
		List  []cargoAuditVulnEntry `json:"list"`
	} `json:"vulnerabilities"`
	Warnings struct {
		Unmaintained []cargoAuditWarningEntry `json:"unmaintained"`
		Yanked       []cargoAuditWarningEntry `json:"yanked"`
		Unsound      []cargoAuditWarningEntry `json:"unsound"`
	} `json:"warnings"`
}

type cargoAuditVulnEntry struct {
	Advisory cargoAuditAdvisory `json:"advisory"`
	Package  cargoAuditPackage  `json:"package"`
}

type cargoAuditAdvisory struct {
	ID            string  `json:"id"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Date          string  `json:"date"`
	URL           string  `json:"url"`
	CVSS          *string `json:"cvss"`
	Informational *string `json:"informational"`
}

type cargoAuditPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cargoAuditWarningEntry struct {
	Kind     string              `json:"kind"`
	Package  cargoAuditPackage   `json:"package"`
	Advisory *cargoAuditAdvisory `json:"advisory"`
}

func (cargoAuditNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading cargo-audit report: %w", err)
	}

	// A genuine `cargo audit --json` report always carries top-level
	// "database" and "lockfile" objects. Their absence means the input is
	// not a recognized cargo-audit report (e.g. another tool's output fed
	// to the wrong adapter), so this is rejected rather than silently
	// yielding zero findings.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("parsing cargo-audit report: %w", err)
	}
	if _, ok := raw["database"]; !ok {
		return nil, 0, fmt.Errorf("cargo-audit report missing required %q field, not a recognized cargo-audit report", "database")
	}
	if _, ok := raw["lockfile"]; !ok {
		return nil, 0, fmt.Errorf("cargo-audit report missing required %q field, not a recognized cargo-audit report", "lockfile")
	}

	var report cargoAuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, fmt.Errorf("parsing cargo-audit report: %w", err)
	}

	vulnCount := report.Vulnerabilities.Count
	vulnListLen := len(report.Vulnerabilities.List)
	if report.Vulnerabilities.Found && vulnCount != vulnListLen {
		return nil, 0, fmt.Errorf("cargo-audit report vulnerabilities.count (%d) does not match len(vulnerabilities.list) (%d)", vulnCount, vulnListLen)
	}
	if vulnCount > 0 && vulnListLen == 0 {
		return nil, 0, fmt.Errorf("cargo-audit report has vulnerabilities.count = %d but an empty vulnerabilities.list", vulnCount)
	}

	findings := make([]types.Finding, 0, len(report.Vulnerabilities.List))

	for _, v := range report.Vulnerabilities.List {
		sev := cargoAuditVulnSeverity(v.Advisory)

		findings = append(findings, types.Finding{
			ID:          v.Advisory.ID,
			Severity:    sev.ToTypesSeverity(),
			Title:       v.Advisory.Title,
			Description: v.Advisory.Description,
			Location:    "Cargo.lock:" + v.Package.Name + "@" + v.Package.Version,
		})
	}

	for _, w := range report.Warnings.Unmaintained {
		findings = append(findings, cargoAuditWarningFinding(w, SeverityLow))
	}
	for _, w := range report.Warnings.Yanked {
		findings = append(findings, cargoAuditWarningFinding(w, SeverityLow))
	}
	for _, w := range report.Warnings.Unsound {
		findings = append(findings, cargoAuditWarningFinding(w, SeverityMedium))
	}

	vulnerableCount := len(report.Vulnerabilities.List)
	passedCount := report.Lockfile.DependencyCount - vulnerableCount
	if passedCount < 0 {
		passedCount = 0
	}

	return findings, passedCount, nil
}

// cargoAuditVulnSeverity determines a vulnerability's canonical severity: a
// parseable CVSS vector is scored via cvssBaseScore and mapped with
// FromCVSS; a missing or unparseable vector maps to high, per
// docs/severity-mapping.md. An advisory with a CVSS field that fails to
// parse is treated the same as one with no CVSS field at all, since the
// tool did supply a value, just not one this adapter can interpret; erroring
// out entirely would drop the finding rather than surfacing it.
func cargoAuditVulnSeverity(advisory cargoAuditAdvisory) Severity {
	if advisory.CVSS == nil || *advisory.CVSS == "" {
		return SeverityHigh
	}

	score, err := cvssBaseScore(*advisory.CVSS)
	if err != nil {
		return SeverityHigh
	}
	return FromCVSS(score)
}

// cargoAuditWarningFinding builds a finding for an unmaintained, yanked, or
// unsound crate warning. Yanked entries do not always carry an advisory, so
// the id falls back to "yanked:<name>@<version>" (or "<kind>:<name>@<version>"
// for other warning kinds without an advisory) when one is absent.
func cargoAuditWarningFinding(w cargoAuditWarningEntry, sev Severity) types.Finding {
	title := w.Kind
	description := ""
	id := w.Kind + ":" + w.Package.Name + "@" + w.Package.Version

	if w.Advisory != nil {
		if w.Advisory.ID != "" {
			id = w.Advisory.ID
		}
		if w.Advisory.Title != "" {
			title = w.Advisory.Title
		}
		description = w.Advisory.Description
	}

	return types.Finding{
		ID:          id,
		Severity:    sev.ToTypesSeverity(),
		Title:       title,
		Description: description,
		Location:    "Cargo.lock:" + w.Package.Name + "@" + w.Package.Version,
	}
}

func init() {
	Register(cargoAuditNormalizer{})
}
