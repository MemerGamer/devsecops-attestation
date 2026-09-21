package normalize

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// genericNormalizer passes through a report that is already in the
// canonical Result shape ({passed?, passed_count?, findings: [...]}).
// It exists so pipelines that already produce canonical JSON (or that use
// a tool without a dedicated adapter) can still go through the normalize
// package uniformly.
//
// Its CheckType is intentionally empty: the generic adapter has no fixed
// tool identity, so the caller must supply --check-type explicitly when
// invoking it from a CLI.
type genericNormalizer struct{}

func (genericNormalizer) Name() string {
	return "generic"
}

func (genericNormalizer) CheckType() string {
	return ""
}

// genericInput mirrors Result. Each finding's severity is re-validated, and
// rewritten to its canonical lowercase form, through ParseSeverity rather
// than trusted blindly from the input file.
type genericInput struct {
	Passed      bool            `json:"passed"`
	PassedCount int             `json:"passed_count"`
	Findings    []types.Finding `json:"findings"`
}

func (g genericNormalizer) Normalize(r io.Reader) ([]types.Finding, int, error) {
	findings, passedCount, _, err := g.normalize(r)
	return findings, passedCount, err
}

// NormalizeWithPass implements ToolPassNormalizer: a canonical generic
// report carries its own explicit "passed" field, which Run combines with
// its threshold-based verdict so a report that self-reports passed:false is
// never silently upgraded to passed:true just because no finding meets the
// caller's --fail-on threshold.
func (g genericNormalizer) NormalizeWithPass(r io.Reader) ([]types.Finding, int, bool, error) {
	return g.normalize(r)
}

func (genericNormalizer) normalize(r io.Reader) ([]types.Finding, int, bool, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, false, fmt.Errorf("reading generic report: %w", err)
	}

	if err := RejectCaseVariantDuplicateKeys(data); err != nil {
		return nil, 0, false, fmt.Errorf("generic report: %w", err)
	}

	var input genericInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, 0, false, fmt.Errorf("parsing generic report: %w", err)
	}

	for i, f := range input.Findings {
		sev, err := ParseSeverity(string(f.Severity))
		if err != nil {
			return nil, 0, false, fmt.Errorf("finding %d (%q): %w", i, f.ID, err)
		}
		input.Findings[i].Severity = sev.ToTypesSeverity()
	}

	if input.Findings == nil {
		input.Findings = []types.Finding{}
	}

	return input.Findings, input.PassedCount, input.Passed, nil
}

func init() {
	Register(genericNormalizer{})
}
