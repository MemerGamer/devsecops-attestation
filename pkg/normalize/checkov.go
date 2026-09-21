package normalize

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// checkovNormalizer translates the JSON output of `checkov -o json` into the
// canonical Result shape. See docs/severity-mapping.md for the severity
// translation this adapter follows.
//
// checkov's `-o json` output takes three shapes depending on invocation:
//
//   - a single object, {"check_type", "results": {...}, "summary": {...}},
//     when scanning with a single framework
//   - a JSON array of such objects, one per framework, for a multi-framework
//     scan
//   - a bare summary object, {"passed", "failed", "skipped",
//     "parsing_errors", "resource_count", "checkov_version"}, when the run
//     found nothing to scan at all (no frameworks matched any file)
//
// This adapter detects and handles all three.
type checkovNormalizer struct{}

func (checkovNormalizer) Name() string {
	return "checkov"
}

func (checkovNormalizer) CheckType() string {
	return "config"
}

type checkovFrameworkReport struct {
	CheckType string         `json:"check_type"`
	Results   checkovResults `json:"results"`
	Summary   checkovSummary `json:"summary"`
}

type checkovResults struct {
	PassedChecks []json.RawMessage    `json:"passed_checks"`
	FailedChecks []checkovFailedCheck `json:"failed_checks"`
}

type checkovFailedCheck struct {
	CheckID       string  `json:"check_id"`
	CheckName     string  `json:"check_name"`
	FilePath      string  `json:"file_path"`
	FileLineRange []int   `json:"file_line_range"`
	Resource      string  `json:"resource"`
	Severity      *string `json:"severity"`
}

type checkovSummary struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Skipped       int `json:"skipped"`
	ParsingErrors int `json:"parsing_errors"`
	ResourceCount int `json:"resource_count"`
}

// checkovEmptyScan is the bare summary object emitted when no framework
// matched anything to scan. It is distinguished from a single framework
// report by the absence of a "results" field.
type checkovEmptyScan struct {
	Passed         int    `json:"passed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	ParsingErrors  int    `json:"parsing_errors"`
	ResourceCount  int    `json:"resource_count"`
	CheckovVersion string `json:"checkov_version"`
}

func (checkovNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading checkov report: %w", err)
	}

	trimmed := skipLeadingSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var reports []checkovFrameworkReport
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, 0, fmt.Errorf("parsing checkov multi-framework report: %w", err)
		}
		return checkovCollect(reports)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("parsing checkov report: %w", err)
	}

	if _, hasResults := raw["results"]; !hasResults {
		// The bare empty-scan summary object is only distinguished from an
		// arbitrary JSON object without a "results" key by carrying
		// checkov-specific fields. Require at least one of them so an
		// unrelated tool's output does not silently normalize to a clean
		// checkov run.
		_, hasVersion := raw["checkov_version"]
		_, hasResourceCount := raw["resource_count"]
		if !hasVersion && !hasResourceCount {
			return nil, 0, fmt.Errorf("checkov report missing required %q or %q field, not a recognized checkov report", "checkov_version", "resource_count")
		}

		var empty checkovEmptyScan
		if err := json.Unmarshal(data, &empty); err != nil {
			return nil, 0, fmt.Errorf("parsing checkov empty-scan report: %w", err)
		}
		if empty.ParsingErrors > 0 && !checkovParsingErrorsIgnorable(checkovSummary{
			Passed:        empty.Passed,
			Failed:        empty.Failed,
			ParsingErrors: empty.ParsingErrors,
			ResourceCount: empty.ResourceCount,
		}) {
			return nil, 0, fmt.Errorf("checkov report has %d parsing error(s), scan incomplete", empty.ParsingErrors)
		}
		return []types.Finding{}, empty.Passed, nil
	}

	var report checkovFrameworkReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, fmt.Errorf("parsing checkov report: %w", err)
	}
	return checkovCollect([]checkovFrameworkReport{report})
}

func checkovCollect(reports []checkovFrameworkReport) ([]types.Finding, int, error) {
	findings := make([]types.Finding, 0)
	passedCount := 0

	for _, report := range reports {
		if report.Summary.ParsingErrors > 0 && !checkovParsingErrorsIgnorable(report.Summary) {
			return nil, 0, fmt.Errorf("checkov report for check_type %q has %d parsing error(s), scan incomplete", report.CheckType, report.Summary.ParsingErrors)
		}

		passedCount += report.Summary.Passed

		for _, fc := range report.Results.FailedChecks {
			sev, err := checkovSeverity(fc.Severity)
			if err != nil {
				return nil, 0, fmt.Errorf("failed check %q: %w", fc.CheckID, err)
			}

			line := 0
			if len(fc.FileLineRange) > 0 {
				line = fc.FileLineRange[0]
			}

			findings = append(findings, types.Finding{
				ID:          fc.CheckID,
				Severity:    sev.ToTypesSeverity(),
				Title:       fc.CheckName,
				Description: fc.Resource,
				Location:    fmt.Sprintf("%s:%d", fc.FilePath, line),
			})
		}
	}

	return findings, passedCount, nil
}

// checkovParsingErrorsIgnorable reports whether a framework's parsing errors
// can be safely ignored rather than failing the scan. This happens when a
// framework configured for the scan (e.g. terraform_plan) attempted to parse
// files that do not actually belong to it (e.g. arbitrary .json files that
// are not Terraform plans); in that case checkov records parsing_errors but
// the framework found zero resources and reported zero passed/failed checks,
// meaning it contributed nothing to the result either way and a parsing
// error there cannot be hiding a real finding. A framework that scanned any
// resources or reported any checks still fails on parsing errors, since a
// parse failure there could be masking findings in the unparsed file.
func checkovParsingErrorsIgnorable(s checkovSummary) bool {
	return s.ResourceCount == 0 && s.Passed == 0 && s.Failed == 0
}

// checkovSeverity maps a checkov failed check's severity field to the
// canonical scale. checkov reports null when no severity is available for a
// given check, which maps to medium.
func checkovSeverity(severity *string) (Severity, error) {
	if severity == nil {
		return SeverityMedium, nil
	}
	return ParseSeverity(*severity)
}

// skipLeadingSpace trims leading JSON whitespace so the top-level type
// (object vs array) can be detected from the first significant byte.
func skipLeadingSpace(data []byte) []byte {
	i := 0
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return data[i:]
		}
	}
	return data[i:]
}

func init() {
	Register(checkovNormalizer{})
}
