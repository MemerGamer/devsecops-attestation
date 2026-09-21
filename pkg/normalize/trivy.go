package normalize

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// trivyNormalizer translates the JSON output of `trivy fs --format json`
// into the canonical Result shape. See docs/severity-mapping.md for the
// severity translation this adapter follows.
type trivyNormalizer struct{}

func (trivyNormalizer) Name() string {
	return "trivy"
}

func (trivyNormalizer) CheckType() string {
	return "sca"
}

// trivyReport mirrors the subset of `trivy fs --format json` output this
// adapter consumes. Results, Vulnerabilities, Misconfigurations and Secrets
// may all be null when a target has nothing to report.
type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string                  `json:"Target"`
	Class             string                  `json:"Class"`
	Type              string                  `json:"Type"`
	Vulnerabilities   []trivyVulnerability    `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfiguration `json:"Misconfigurations"`
	Secrets           []trivySecret           `json:"Secrets"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

type trivyMisconfiguration struct {
	ID            string                  `json:"ID"`
	Title         string                  `json:"Title"`
	Description   string                  `json:"Description"`
	Severity      string                  `json:"Severity"`
	CauseMetadata trivyMisconfigCauseMeta `json:"CauseMetadata"`
}

type trivyMisconfigCauseMeta struct {
	StartLine int `json:"StartLine"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

func (trivyNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading trivy report: %w", err)
	}

	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, fmt.Errorf("parsing trivy report: %w", err)
	}

	// trivy's JSON schema is versioned; this adapter only understands
	// schema version 2 (the current `trivy fs --format json` output). A
	// missing or different SchemaVersion means the input is not a
	// recognized trivy report (e.g. another tool's output fed to the wrong
	// adapter, or a future/past schema this adapter has not been updated
	// for), so it is rejected rather than silently yielding zero findings.
	if report.SchemaVersion != 2 {
		return nil, 0, fmt.Errorf("trivy report has SchemaVersion %d, want 2 (not a recognized trivy report)", report.SchemaVersion)
	}

	var findings []types.Finding

	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			sev, err := ParseSeverity(vuln.Severity)
			if err != nil {
				return nil, 0, fmt.Errorf("vulnerability %q: %w", vuln.VulnerabilityID, err)
			}

			title := vuln.Title
			if title == "" {
				title = fmt.Sprintf("%s %s", vuln.PkgName, vuln.InstalledVersion)
			}

			findings = append(findings, types.Finding{
				ID:          vuln.VulnerabilityID,
				Severity:    sev.ToTypesSeverity(),
				Title:       title,
				Description: vuln.Description,
				Location:    fmt.Sprintf("%s:%s@%s", res.Target, vuln.PkgName, vuln.InstalledVersion),
			})
		}

		for _, mis := range res.Misconfigurations {
			sev, err := ParseSeverity(mis.Severity)
			if err != nil {
				return nil, 0, fmt.Errorf("misconfiguration %q: %w", mis.ID, err)
			}

			findings = append(findings, types.Finding{
				ID:          mis.ID,
				Severity:    sev.ToTypesSeverity(),
				Title:       mis.Title,
				Description: mis.Description,
				Location:    fmt.Sprintf("%s:%d", res.Target, mis.CauseMetadata.StartLine),
			})
		}

		for _, sec := range res.Secrets {
			sev, err := ParseSeverity(sec.Severity)
			if err != nil {
				return nil, 0, fmt.Errorf("secret %q: %w", sec.RuleID, err)
			}

			findings = append(findings, types.Finding{
				ID:          sec.RuleID,
				Severity:    sev.ToTypesSeverity(),
				Title:       sec.Title,
				Description: sec.Category,
				Location:    fmt.Sprintf("%s:%d", res.Target, sec.StartLine),
			})
		}
	}

	return findings, 0, nil
}

func init() {
	Register(trivyNormalizer{})
}
