// Package normalize adapts the native JSON output of third-party security
// tools (semgrep, trivy, checkov, gitleaks, and others) into the canonical
// Result shape expected by the sign CLI's --result flag.
//
// See doc.go for the adapter contract that tool-specific implementations
// must follow.
package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
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

// RejectCaseVariantDuplicateKeys streams obj (a JSON object) token by token
// and returns an error if two keys collide: either exact duplicates, e.g.
// {"results": [...], "results": []}, or keys equal under strings.EqualFold,
// e.g. {"results": [...], "RESULTS": []} or {"reſults": [...], "results": []}
// (U+017F LATIN SMALL LETTER LONG S folds to "s" under Unicode simple case
// folding, the same folding strings.EqualFold and encoding/json's own field
// matching use).
//
// Decoding obj into a map[string]json.RawMessage, as an earlier version of
// this function did, cannot catch the exact-duplicate case: encoding/json
// resolves two identical keys in the same object by silently keeping
// whichever value appears later, so by the time the map exists the
// collision is already gone. Comparing with strings.ToLower also misses
// Unicode fold variants such as the long s or the Kelvin sign (U+212A,
// which folds to "k") that are not plain ASCII case changes. Streaming the
// object with json.Decoder.Token lets every key be seen and compared,
// exactly as it appeared on the wire, before any collision resolution
// happens.
//
// Adapters call this on the top-level report object, and again on any
// nested object whose keys they rely on to enumerate findings, before
// decoding into their own structs. Only the keys directly inside obj are
// checked; nested objects are skipped over (not recursed into), matching
// the one-level behavior adapters rely on at every nesting level they call
// this at.
//
// obj must itself already be valid JSON (typically a json.RawMessage
// captured from an outer decode) whose top-level value is an object; a
// non-object value, invalid JSON, or trailing data after the object is
// reported as an error rather than silently skipped, since a normalizer
// that calls this expects exactly one object at this position.
func RejectCaseVariantDuplicateKeys(obj json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(obj))

	open, err := dec.Token()
	if err != nil {
		return fmt.Errorf("expected a JSON object for duplicate-key check: %w", err)
	}
	delim, ok := open.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("expected a JSON object for duplicate-key check, got %v", open)
	}

	// seen holds every key exactly as it appeared, in the order it was
	// read. Each new key is compared against all of them; objects have few
	// enough keys that the O(n^2) scan is not a concern, and it is simpler
	// and harder to get wrong than a folded-key map lookup.
	var seen []string

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("reading JSON object key for duplicate-key check: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("expected a JSON object key, got %v", keyTok)
		}

		// Consume and discard the value (whatever shape it is) without
		// recursing into it for duplicate keys of its own; callers that
		// care about a nested object's keys call this function again on
		// that nested json.RawMessage themselves.
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("reading value for JSON key %q: %w", key, err)
		}

		for _, original := range seen {
			if original == key {
				return fmt.Errorf("duplicate JSON key %q: ambiguous report, rejected", key)
			}
			if strings.EqualFold(original, key) {
				return fmt.Errorf("duplicate JSON key %q (case-insensitively equal to %q): ambiguous report, rejected", key, original)
			}
		}
		seen = append(seen, key)
	}

	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("reading closing brace for duplicate-key check: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing data after JSON object for duplicate-key check")
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
