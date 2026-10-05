package normalize

import (
	"os"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func TestGenericNormalizer_NameAndCheckType(t *testing.T) {
	n := genericNormalizer{}
	if n.Name() != "generic" {
		t.Errorf("Name() = %q, want %q", n.Name(), "generic")
	}
	if n.CheckType() != "" {
		t.Errorf("CheckType() = %q, want empty", n.CheckType())
	}
}

func TestGenericNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/generic/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := genericNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passedCount != 12 {
			t.Errorf("passedCount = %d, want 12", passedCount)
		}
	})

	t.Run("findings report is passed through", func(t *testing.T) {
		f, err := os.Open("testdata/generic/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := genericNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("len(findings) = %d, want 2", len(findings))
		}
		if passedCount != 5 {
			t.Errorf("passedCount = %d, want 5", passedCount)
		}
		if findings[0].ID != "FIND-001" || findings[1].ID != "FIND-002" {
			t.Errorf("unexpected finding IDs: %+v", findings)
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/generic/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = genericNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("finding with invalid severity returns error", func(t *testing.T) {
		bad := `{"passed": false, "passed_count": 0, "findings": [{"id": "x", "severity": "nonsense", "title": "t"}]}`
		_, _, err := genericNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for invalid finding severity, got nil")
		}
	})

	t.Run("nil findings normalize to empty slice", func(t *testing.T) {
		findings, _, err := genericNormalizer{}.Normalize(stringsReader(`{"passed": true, "passed_count": 0}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if findings == nil {
			t.Error("findings should be non-nil empty slice")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := genericNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("severity is rewritten to canonical lowercase form", func(t *testing.T) {
		in := `{"passed": false, "passed_count": 0, "findings": [{"id": "x", "severity": "HIGH", "title": "t"}, {"id": "y", "severity": "moderate", "title": "u"}]}`
		findings, _, err := genericNormalizer{}.Normalize(stringsReader(in))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if findings[0].Severity != types.Severity("high") {
			t.Errorf("findings[0].Severity = %q, want %q (rewritten from HIGH)", findings[0].Severity, "high")
		}
		if findings[1].Severity != types.Severity("medium") {
			t.Errorf("findings[1].Severity = %q, want %q (rewritten from moderate synonym)", findings[1].Severity, "medium")
		}
	})
}

func TestGenericNormalizer_NormalizeWithPass(t *testing.T) {
	t.Run("carries through an explicit passed:false with no findings", func(t *testing.T) {
		in := `{"passed": false, "passed_count": 0, "findings": []}`
		findings, passedCount, toolPassed, err := genericNormalizer{}.NormalizeWithPass(stringsReader(in))
		if err != nil {
			t.Fatalf("NormalizeWithPass() error = %v", err)
		}
		if toolPassed {
			t.Error("toolPassed = true, want false")
		}
		if len(findings) != 0 || passedCount != 0 {
			t.Errorf("findings/passedCount = %v/%d, want empty/0", findings, passedCount)
		}
	})

	t.Run("carries through an explicit passed:true", func(t *testing.T) {
		findings, _, toolPassed, err := genericNormalizer{}.NormalizeWithPass(stringsReader(`{"passed": true, "passed_count": 0, "findings": []}`))
		if err != nil {
			t.Fatalf("NormalizeWithPass() error = %v", err)
		}
		if !toolPassed {
			t.Error("toolPassed = false, want true")
		}
		_ = findings
	})
}

// TestRun_GenericAdapter_ToolReportedPassIsHonored verifies the bug fix: a
// canonical report with passed:false and no findings must not be silently
// upgraded to Result.Passed = true just because no finding meets the
// threshold.
func TestRun_GenericAdapter_ToolReportedPassIsHonored(t *testing.T) {
	result, err := Run("generic", stringsReader(`{"passed": false, "passed_count": 0, "findings": []}`), SeverityCritical)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Passed {
		t.Error("result.Passed = true, want false (tool self-reported passed:false)")
	}
}

func TestGenericNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("generic")
	if err != nil {
		t.Fatalf("Get(generic) error = %v", err)
	}
	if n.Name() != "generic" {
		t.Errorf("Get(generic).Name() = %q, want %q", n.Name(), "generic")
	}
}

func TestRun_GenericAdapter(t *testing.T) {
	t.Run("passes when no finding meets threshold and tool reports passed:true", func(t *testing.T) {
		// A self-contained report with passed:true, distinct from
		// testdata/generic/findings.json (which self-reports passed:false),
		// so this isolates the threshold-only pass path from the
		// tool-reported pass state exercised by
		// TestRun_GenericAdapter_ToolReportedPassIsHonored.
		in := `{"passed": true, "passed_count": 1, "findings": [{"id": "FIND-001", "severity": "low", "title": "t"}]}`
		result, err := Run("generic", stringsReader(in), SeverityCritical)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no critical findings, tool reports passed:true)")
		}
	})

	t.Run("fails when a finding meets or exceeds threshold", func(t *testing.T) {
		f, err := os.Open("testdata/generic/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("generic", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a high finding is present)")
		}
	})

	t.Run("unknown adapter name returns error", func(t *testing.T) {
		_, err := Run("does-not-exist", stringsReader("{}"), SeverityHigh)
		if err == nil {
			t.Error("Run() expected error for unknown adapter, got nil")
		}
	})

	t.Run("normalize error is propagated", func(t *testing.T) {
		_, err := Run("generic", stringsReader("not json"), SeverityHigh)
		if err == nil {
			t.Error("Run() expected error for invalid input, got nil")
		}
	})
}

func TestResult_MarshalIndent(t *testing.T) {
	r := Result{Passed: true, PassedCount: 1}
	data, err := r.MarshalIndent()
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("MarshalIndent() returned empty output")
	}
}

func TestGenericNormalizer_DuplicateCaseVariantKeyRejected(t *testing.T) {
	input := `{"passed":true,"Passed":false,"findings":[]}`
	_, _, _, err := genericNormalizer{}.normalize(stringsReader(input))
	if err == nil {
		t.Error("normalize() expected error for case-variant duplicate top-level key, got nil")
	}
}
