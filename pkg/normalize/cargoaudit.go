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
	if err := RejectCaseVariantDuplicateKeys(data); err != nil {
		return nil, 0, fmt.Errorf("cargo-audit report: %w", err)
	}

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
	if vulnsRaw, ok := raw["vulnerabilities"]; ok {
		if err := RejectCaseVariantDuplicateKeys(vulnsRaw); err != nil {
			return nil, 0, fmt.Errorf("cargo-audit report %q object: %w", "vulnerabilities", err)
		}
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
// FromCVSS; a missing CVSS field (the tool supplied no vector at all) maps
// to high, per docs/severity-mapping.md.
//
// A CVSS field that is present but fails to parse - including a CVSS:4.0
// vector, which this adapter's parser does not support - maps to critical
// rather than high. This is deliberately fail-closed: the tool did supply a
// score, this adapter just cannot interpret it, so treating that the same
// as "no score at all" would silently under-report an advisory that might
// be critical. Parsing CVSS 4.0 properly is left as future work; until
// then, an unparseable vector is assumed to be at least as severe as the
// worst score this adapter can express.
func cargoAuditVulnSeverity(advisory cargoAuditAdvisory) Severity {
	if advisory.CVSS == nil || *advisory.CVSS == "" {
		return SeverityHigh
	}

	score, err := cvssBaseScore(*advisory.CVSS)
	if err != nil {
		return SeverityCritical
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
