package normalize

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// semgrepNormalizer translates the JSON output of `semgrep --json` into the
// canonical Result shape. See docs/severity-mapping.md for the severity
// translation this adapter follows.
type semgrepNormalizer struct{}

func (semgrepNormalizer) Name() string {
	return "semgrep"
}

func (semgrepNormalizer) CheckType() string {
	return "sast"
}

// semgrepReport mirrors the subset of `semgrep --json` output this adapter
// consumes. Unrecognized fields are ignored by encoding/json.
type semgrepReport struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
	Paths   *semgrepPaths   `json:"paths"`
}

// semgrepError mirrors one entry of the `errors` array in a semgrep report.
// Semgrep reports partial-parse problems (syntax errors in a single target
// file, timeouts on one rule, etc.) at "warn" level alongside hard failures
// at "error" level; only the latter should abort normalization, since a
// warn-level entry means a subset of the scan was degraded, not that the
// scan overall failed. See docs/severity-mapping.md for the full rule.
type semgrepError struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// isBlocking reports whether a semgrep error entry should cause
// normalization to fail. An entry with level "error" is blocking. An entry
// with no level at all is treated as blocking too, fail-closed, since older
// or unexpected semgrep output should not silently be accepted. Any other
// level ("warn", "warning", etc.) is treated as a partial-parse notice and
// does not block.
func (e semgrepError) isBlocking() bool {
	level := strings.ToLower(strings.TrimSpace(e.Level))
	return level == "" || level == "error"
}

type semgrepPaths struct {
	Scanned []string `json:"scanned"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string         `json:"message"`
	Severity string         `json:"severity"`
	Metadata map[string]any `json:"metadata"`
}

func (semgrepNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading semgrep report: %w", err)
	}

	// A genuine `semgrep --json` report always carries a top-level "results"
	// key, even when it is an empty array. Its absence means the input is
	// not a recognized semgrep report (e.g. another tool's output fed to
	// the wrong adapter), so this is rejected rather than silently yielding
	// zero findings.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("parsing semgrep report: %w", err)
	}
	if _, ok := raw["results"]; !ok {
		return nil, 0, fmt.Errorf("semgrep report missing required %q field, not a recognized semgrep report", "results")
	}

	var report semgrepReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, 0, fmt.Errorf("parsing semgrep report: %w", err)
	}

	blocking := 0
	for _, e := range report.Errors {
		if e.isBlocking() {
			blocking++
		}
	}
	if blocking > 0 {
		return nil, 0, fmt.Errorf("semgrep report contains %d error-level scan error(s), scan incomplete", blocking)
	}

	findings := make([]types.Finding, 0, len(report.Results))
	for _, res := range report.Results {
		sev, err := semgrepSeverity(res.Extra.Severity)
		if err != nil {
			return nil, 0, fmt.Errorf("result %q: %w", res.CheckID, err)
		}

		findings = append(findings, types.Finding{
			ID:          res.CheckID,
			Severity:    sev.ToTypesSeverity(),
			Title:       semgrepTitle(res),
			Description: res.Extra.Message,
			Location:    fmt.Sprintf("%s:%d", res.Path, res.Start.Line),
		})
	}

	passedCount := 0
	if report.Paths != nil {
		passedCount = len(report.Paths.Scanned)
	}

	return findings, passedCount, nil
}

// semgrepTitle derives a short title from a semgrep result: the last
// dot-separated segment of the check ID when available, falling back to the
// first line of the message when the check ID has no dotted segments.
func semgrepTitle(res semgrepResult) string {
	if res.CheckID != "" {
		segments := strings.Split(res.CheckID, ".")
		last := segments[len(segments)-1]
		if last != "" {
			return last
		}
	}

	message := res.Extra.Message
	if idx := strings.IndexByte(message, '\n'); idx >= 0 {
		return message[:idx]
	}
	return message
}

// semgrepSeverity maps semgrep's native severity vocabulary to the canonical
// scale. The legacy three-level vocabulary keeps its historical mapping:
// ERROR -> high, WARNING -> medium, INFO -> low. Current semgrep versions
// also emit the canonical five-level vocabulary directly (CRITICAL, HIGH,
// MEDIUM, LOW), which is parsed case-insensitively via ParseSeverity.
func semgrepSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return SeverityHigh, nil
	case "WARNING":
		return SeverityMedium, nil
	case "INFO":
		return SeverityLow, nil
	default:
		sev, err := ParseSeverity(s)
		if err != nil {
			return 0, fmt.Errorf("unrecognized semgrep severity %q", s)
		}
		return sev, nil
	}
}

func init() {
	Register(semgrepNormalizer{})
}
