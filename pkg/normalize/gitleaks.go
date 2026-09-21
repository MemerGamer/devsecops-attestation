package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// gitleaksNormalizer translates a gitleaks JSON report
// (`gitleaks detect --report-format json`) into the canonical Result shape.
//
// gitleaks reports a bare JSON array of findings, or an empty array "[]"
// when no secrets are found; there is no wrapping object and no pass count.
// A genuinely empty (zero-byte or whitespace-only) file is not treated as
// clean: gitleaks always writes at least "[]", so an empty file means the
// scanner crashed or was killed before it could write a report, and that
// must be surfaced as an error rather than silently passed. Every finding
// is treated as critical: a committed secret is a hard failure condition
// independent of any confidence score gitleaks might report, per
// docs/severity-mapping.md.
type gitleaksNormalizer struct{}

func (gitleaksNormalizer) Name() string {
	return "gitleaks"
}

func (gitleaksNormalizer) CheckType() string {
	return "secret"
}

// gitleaksFinding mirrors the fields gitleaks emits for a single leak.
//
// Match and Secret are intentionally read into this struct (so malformed
// input that includes them still parses) but are never copied into a
// types.Finding: propagating the leaked credential itself into the
// attestation chain would turn the attestation into a second leak.
type gitleaksFinding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

func (gitleaksNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("reading gitleaks report: %w", err)
	}

	// An empty or whitespace-only file is not a valid gitleaks report: a
	// clean scan always writes at least "[]". A genuinely empty file means
	// the scanner crashed or was killed before writing its report, and that
	// must not be silently treated as a clean pass.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, 0, fmt.Errorf("gitleaks report is empty, cannot distinguish a clean scan from a crashed or incomplete one")
	}

	var raw []gitleaksFinding
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, 0, fmt.Errorf("parsing gitleaks report: %w", err)
	}

	findings := make([]types.Finding, 0, len(raw))
	for _, gf := range raw {
		id := gf.Fingerprint
		if id == "" {
			id = gf.RuleID + ":" + gf.File + ":" + strconv.Itoa(gf.StartLine)
		}

		findings = append(findings, types.Finding{
			ID:          id,
			Severity:    SeverityCritical.ToTypesSeverity(),
			Title:       gf.RuleID,
			Description: gf.Description,
			Location:    gf.File + ":" + strconv.Itoa(gf.StartLine),
		})
	}

	return findings, 0, nil
}

func init() {
	Register(gitleaksNormalizer{})
}
