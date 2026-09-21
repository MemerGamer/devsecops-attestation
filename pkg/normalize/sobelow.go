package normalize

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// sobelowNormalizer translates the JSON output of `mix sobelow --format
// json` into the canonical Result shape. See docs/severity-mapping.md for
// the severity translation this adapter follows.
type sobelowNormalizer struct{}

func (sobelowNormalizer) Name() string {
	return "sobelow"
}

func (sobelowNormalizer) CheckType() string {
	return "sast"
}

// sobelowReport mirrors the subset of `mix sobelow --format json` output
// this adapter consumes. Sobelow groups findings into three confidence
// buckets rather than reporting a severity field per finding.
type sobelowReport struct {
	SobelowVersion string         `json:"sobelow_version"`
	TotalFindings  int            `json:"total_findings"`
	Findings       sobelowFinding `json:"findings"`
}

type sobelowFinding struct {
	High   []sobelowEntry `json:"high_confidence"`
	Medium []sobelowEntry `json:"medium_confidence"`
	Low    []sobelowEntry `json:"low_confidence"`
}

type sobelowEntry struct {
	Type     string `json:"type"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
}

func (sobelowNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading sobelow report: %w", err)
	}

	if err := RejectCaseVariantDuplicateKeys(data); err != nil {
		return nil, 0, fmt.Errorf("sobelow report: %w", err)
	}

	var report sobelowReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, fmt.Errorf("parsing sobelow report: %w", err)
	}

	// A genuine `mix sobelow --format json` report always carries a
	// non-empty sobelow_version. Its absence means the input is not a
	// recognized sobelow report (e.g. another tool's output fed to the
	// wrong adapter), so this is rejected rather than silently yielding
	// zero findings.
	if report.SobelowVersion == "" {
		return nil, 0, fmt.Errorf("sobelow report missing required %q field, not a recognized sobelow report", "sobelow_version")
	}

	findings := make([]types.Finding, 0, report.TotalFindings)
	findings = appendSobelowEntries(findings, report.Findings.High, SeverityHigh)
	findings = appendSobelowEntries(findings, report.Findings.Medium, SeverityMedium)
	findings = appendSobelowEntries(findings, report.Findings.Low, SeverityLow)

	// Sobelow does not report a passed-check count; a clean run is
	// signaled entirely by an empty findings list.
	return findings, 0, nil
}

// appendSobelowEntries converts one confidence bucket's entries into
// canonical findings at the given severity and appends them to findings.
func appendSobelowEntries(findings []types.Finding, entries []sobelowEntry, sev Severity) []types.Finding {
	for _, e := range entries {
		findings = append(findings, types.Finding{
			ID:       fmt.Sprintf("%s:%s:%d", sobelowSlug(e.Type), e.File, e.Line),
			Severity: sev.ToTypesSeverity(),
			Title:    e.Type,
			Location: fmt.Sprintf("%s:%d", e.File, e.Line),
		})
	}
	return findings
}

// sobelowSlug normalizes a sobelow finding type (e.g. "SQL injection") into
// a stable, id-safe slug (e.g. "sql-injection") so the derived finding ID
// stays consistent across reports even if whitespace in the type string
// varies.
func sobelowSlug(s string) string {
	fields := strings.Fields(strings.ToLower(s))
	return strings.Join(fields, "-")
}

func init() {
	Register(sobelowNormalizer{})
}
