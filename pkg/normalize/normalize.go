// Package normalize adapts the native JSON output of third-party security
// tools (semgrep, trivy, checkov, gitleaks, and others) into the canonical
// Result shape expected by the sign CLI's --result flag.
//
// See doc.go for the adapter contract that tool-specific implementations
// must follow.
package normalize

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// Result is the canonical, tool-agnostic shape produced by a Normalizer.
// Its JSON encoding matches exactly what cmd/sign's --result flag expects
// (see scanResultInput in cmd/sign/main.go), so a Result can be marshaled
// straight to a file and passed to `sign --result` unchanged.
type Result struct {
	Passed      bool            `json:"passed"`
	PassedCount int             `json:"passed_count"`
	Findings    []types.Finding `json:"findings"`
}

// Normalizer converts one security tool's native report format into a
// canonical list of findings plus a pass count. Each supported tool
// implements this interface in its own file and registers an instance
// with Register in an init() function.
type Normalizer interface {
	// Name returns the adapter's identifier, e.g. "semgrep" or "trivy".
	// Names must be unique across all registered adapters.
	Name() string

	// CheckType returns the security check type this adapter's tool
	// produces, e.g. "sast" or "sca". The generic adapter returns "" since
	// its check type is supplied by the caller via --check-type instead.
	CheckType() string

	// Normalize reads a tool's native report from r and returns the
	// translated findings plus the number of checks that passed (as
	// reported by the tool, or zero when the tool does not report a pass
	// count). It does not decide pass/fail for the run as a whole; that is
	// determined by Run based on the caller-supplied failOn threshold.
	Normalize(r io.Reader) (findings []types.Finding, passedCount int, err error)
}

// ToolPassNormalizer is an optional interface a Normalizer may additionally
// implement when its underlying tool reports its own pass/fail verdict
// independently of the translated findings list, for example mix_audit's
// top-level "pass" boolean or a canonical generic report's own "passed"
// field. When the adapter Run selects implements this interface,
// NormalizeWithPass is called instead of Normalize, and the tool-reported
// verdict is combined with Run's own threshold-based verdict via logical
// AND: the run passes only when both agree it passed.
//
// This is a separate, optional interface rather than an additional return
// value on Normalize itself because only a minority of adapters have a
// tool-reported pass state to report; adding an always-unused return value
// to every other adapter's Normalize would be needless noise.
type ToolPassNormalizer interface {
	Normalizer

	// NormalizeWithPass behaves exactly like Normalize but additionally
	// returns the tool's own reported pass state for this report.
	NormalizeWithPass(r io.Reader) (findings []types.Finding, passedCount int, toolPassed bool, err error)
}

// registry holds all registered Normalizer adapters, keyed by name.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Normalizer)
)

// Register adds a Normalizer to the package-level registry under its Name().
// It panics if an adapter with the same name is already registered, since
// this indicates a programming error (two adapters claiming the same tool)
// that must be caught immediately rather than silently shadowing one adapter
// with another.
func Register(n Normalizer) {
	registryMu.Lock()
	defer registryMu.Unlock()

	name := n.Name()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("normalize: adapter %q already registered", name))
	}
	registry[name] = n
}

// Get looks up a registered Normalizer by name.
func Get(name string) (Normalizer, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	n, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("no normalizer registered for %q", name)
	}
	return n, nil
}

// Names returns the names of all registered adapters, sorted alphabetically.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Run looks up the named adapter, normalizes the report read from r, and
// computes Result.Passed: the run passes when no finding has a severity at
// or above failOn, AND (when the adapter implements ToolPassNormalizer) the
// tool's own reported pass state is not false. failOn is inclusive, matching
// the deploy gate's zero-tolerance semantics (e.g. failOn = SeverityHigh
// rejects both high and critical findings).
func Run(name string, r io.Reader, failOn Severity) (Result, error) {
	n, err := Get(name)
	if err != nil {
		return Result{}, fmt.Errorf("running normalizer: %w", err)
	}

	var findings []types.Finding
	var passedCount int
	var toolPassed *bool

	if tpn, ok := n.(ToolPassNormalizer); ok {
		var tp bool
		findings, passedCount, tp, err = tpn.NormalizeWithPass(r)
		toolPassed = &tp
	} else {
		findings, passedCount, err = n.Normalize(r)
	}
	if err != nil {
		return Result{}, fmt.Errorf("normalizing %q report: %w", name, err)
	}
	if findings == nil {
		findings = []types.Finding{}
	}

	passed := true
	for _, f := range findings {
		sev, err := ParseSeverity(string(f.Severity))
		if err != nil {
			return Result{}, fmt.Errorf("finding %q has invalid severity %q: %w", f.ID, f.Severity, err)
		}
		if sev >= failOn {
			passed = false
			break
		}
	}
	if toolPassed != nil && !*toolPassed {
		passed = false
	}

	return Result{
		Passed:      passed,
		PassedCount: passedCount,
		Findings:    findings,
	}, nil
}

// RejectCaseVariantDuplicateKeys decodes obj (a JSON object) into a
// map[string]json.RawMessage and returns an error if two keys are equal
// under strings.EqualFold, e.g. {"results": [...], "RESULTS": []}.
// encoding/json's decoding into a struct silently resolves such collisions
// by matching the struct field case-insensitively and keeping whichever
// value appears later in the object, which lets a second, differently-cased
// copy of a findings-bearing key silently replace (or coexist unnoticed
// with) the one an adapter's struct tags expect. Adapters call this on the
// top-level report object, and again on any nested object whose keys they
// rely on to enumerate findings, before decoding into their own structs.
//
// obj must itself already be valid JSON (typically a json.RawMessage
// captured from an outer decode); a non-object value (or invalid JSON) is
// reported as an error rather than silently skipped, since a normalizer
// that calls this expects an object at this position.
func RejectCaseVariantDuplicateKeys(obj json.RawMessage) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(obj, &raw); err != nil {
		return fmt.Errorf("expected a JSON object for duplicate-key check: %w", err)
	}

	seen := make(map[string]string, len(raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		folded := strings.ToLower(k)
		if original, ok := seen[folded]; ok {
			return fmt.Errorf("duplicate JSON key %q (case-insensitively equal to %q): ambiguous report, rejected", k, original)
		}
		seen[folded] = k
	}
	return nil
}

// MarshalIndent is a convenience wrapper that encodes a Result exactly as
// the sign CLI's --result flag expects it, with indentation for readability
// when written to a file that a human might inspect.
func (r Result) MarshalIndent() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling normalize result: %w", err)
	}
	return data, nil
}
