package normalize

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// stringsReader is a small helper returning an io.Reader over a string,
// avoiding an import alias clash with the strings package in test bodies.
func stringsReader(s string) io.Reader {
	return strings.NewReader(s)
}

// errReader is an io.Reader that always fails, used to exercise error paths
// that depend on a read failure rather than malformed content.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

// fakeNormalizer is a minimal Normalizer used to test the registry in
// isolation from the generic adapter.
type fakeNormalizer struct {
	name      string
	checkType string
}

func (f fakeNormalizer) Name() string      { return f.name }
func (f fakeNormalizer) CheckType() string { return f.checkType }
func (f fakeNormalizer) Normalize(io.Reader) ([]types.Finding, int, error) {
	return []types.Finding{{ID: "fake-1", Severity: types.SeverityLow, Title: "fake finding"}}, 3, nil
}

func TestRegister_And_Get(t *testing.T) {
	Register(fakeNormalizer{name: "fake-tool-a", checkType: "sast"})

	n, err := Get("fake-tool-a")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if n.Name() != "fake-tool-a" {
		t.Errorf("Name() = %q, want %q", n.Name(), "fake-tool-a")
	}
	if n.CheckType() != "sast" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sast")
	}
}

func TestRegister_PanicsOnDuplicate(t *testing.T) {
	Register(fakeNormalizer{name: "fake-tool-b"})

	defer func() {
		if r := recover(); r == nil {
			t.Error("Register() expected panic for duplicate name, got none")
		}
	}()
	Register(fakeNormalizer{name: "fake-tool-b"})
}

func TestGet_UnknownReturnsError(t *testing.T) {
	_, err := Get("totally-unregistered-adapter")
	if err == nil {
		t.Error("Get() expected error for unregistered adapter, got nil")
	}
}

func TestNames_IsSortedAndContainsRegistered(t *testing.T) {
	Register(fakeNormalizer{name: "zzz-fake-tool"})
	Register(fakeNormalizer{name: "aaa-fake-tool"})

	names := Names()
	if !sortedStrings(names) {
		t.Errorf("Names() not sorted: %v", names)
	}

	foundA, foundZ := false, false
	for _, n := range names {
		if n == "aaa-fake-tool" {
			foundA = true
		}
		if n == "zzz-fake-tool" {
			foundZ = true
		}
	}
	if !foundA || !foundZ {
		t.Errorf("Names() = %v, expected to contain aaa-fake-tool and zzz-fake-tool", names)
	}
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

func TestRun_WithFakeNormalizer(t *testing.T) {
	Register(fakeNormalizer{name: "fake-tool-c"})

	result, err := Run("fake-tool-c", stringsReader(""), SeverityMedium)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Passed {
		t.Error("result.Passed = false, want true (only a low-severity finding present)")
	}
	if result.PassedCount != 3 {
		t.Errorf("PassedCount = %d, want 3", result.PassedCount)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
}

func TestRun_FailsClosedOnInvalidFindingSeverity(t *testing.T) {
	Register(badSeverityNormalizer{})

	_, err := Run("bad-severity-tool", stringsReader(""), SeverityHigh)
	if err == nil {
		t.Error("Run() expected error for invalid finding severity, got nil")
	}
}

type badSeverityNormalizer struct{}

func (badSeverityNormalizer) Name() string      { return "bad-severity-tool" }
func (badSeverityNormalizer) CheckType() string { return "sast" }
func (badSeverityNormalizer) Normalize(io.Reader) ([]types.Finding, int, error) {
	return []types.Finding{{ID: "x", Severity: types.Severity("not-a-severity")}}, 0, nil
}

func TestRejectCaseVariantDuplicateKeys(t *testing.T) {
	t.Run("unique keys pass", func(t *testing.T) {
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":[],"errors":[]}`))
		if err != nil {
			t.Errorf("unexpected error = %v, want nil", err)
		}
	})

	t.Run("exact duplicate key", func(t *testing.T) {
		// map[string]json.RawMessage decoding collapses two identical keys
		// into one entry by keeping the later value, so this case is only
		// caught by streaming the object with json.Decoder.Token instead of
		// unmarshaling it into a map first.
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":[1],"results":[]}`))
		if err == nil {
			t.Error("expected error for exact duplicate key, got nil")
		}
	})

	t.Run("ASCII case variant", func(t *testing.T) {
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":[],"RESULTS":[]}`))
		if err == nil {
			t.Error("expected error for ASCII case-variant key, got nil")
		}
	})

	t.Run("long s Unicode fold variant", func(t *testing.T) {
		// U+017F LATIN SMALL LETTER LONG S (ſ) folds to "s" under Unicode
		// simple case folding, so "reſults" and "results" collide; a plain
		// strings.ToLower comparison would miss this since ToLower leaves ſ
		// unchanged.
		err := RejectCaseVariantDuplicateKeys([]byte(`{"re` + "ſ" + `ults":[],"results":[]}`))
		if err == nil {
			t.Error("expected error for long-s Unicode fold variant key, got nil")
		}
	})

	t.Run("Kelvin sign Unicode fold variant", func(t *testing.T) {
		// U+212A KELVIN SIGN (K) folds to "k" under Unicode simple case
		// folding, so "K" and "k" collide even though neither is the ASCII
		// letter K's case pair of the other.
		err := RejectCaseVariantDuplicateKeys([]byte(`{"` + "K" + `":[],"k":[]}`))
		if err == nil {
			t.Error("expected error for Kelvin-sign Unicode fold variant key, got nil")
		}
	})

	t.Run("non-object input rejected", func(t *testing.T) {
		err := RejectCaseVariantDuplicateKeys([]byte(`[1,2,3]`))
		if err == nil {
			t.Error("expected error for non-object input, got nil")
		}
	})

	t.Run("invalid JSON rejected", func(t *testing.T) {
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":`))
		if err == nil {
			t.Error("expected error for invalid JSON, got nil")
		}
	})

	t.Run("trailing data after object rejected", func(t *testing.T) {
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":[]} {"results":[]}`))
		if err == nil {
			t.Error("expected error for trailing data after object, got nil")
		}
	})

	t.Run("nested objects are not recursed into", func(t *testing.T) {
		// A duplicate inside a nested object is not this function's
		// concern at this call; callers that care about a nested object's
		// keys call this function again on that nested value themselves.
		err := RejectCaseVariantDuplicateKeys([]byte(`{"results":{"a":1,"A":2}}`))
		if err != nil {
			t.Errorf("unexpected error = %v, want nil (nested duplicate not checked at this level)", err)
		}
	})
}
