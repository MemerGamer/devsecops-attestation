package normalize

import (
	"fmt"
	"os"
	"testing"
)

func TestSemgrepNormalizer_NameAndCheckType(t *testing.T) {
	n := semgrepNormalizer{}
	if n.Name() != "semgrep" {
		t.Errorf("Name() = %q, want %q", n.Name(), "semgrep")
	}
	if n.CheckType() != "sast" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sast")
	}
}

func TestSemgrepNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings and passed count from scanned paths", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := semgrepNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passedCount != 3 {
			t.Errorf("passedCount = %d, want 3", passedCount)
		}
	})

	t.Run("findings report maps each severity, title and location", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := semgrepNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 4 {
			t.Fatalf("len(findings) = %d, want 4", len(findings))
		}
		if passedCount != 4 {
			t.Errorf("passedCount = %d, want 4", passedCount)
		}

		tests := []struct {
			idx       int
			wantID    string
			wantSev   string
			wantLoc   string
			wantTitle string
		}{
			{0, "python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use", "high", "src/runner.py:42", "dangerous-subprocess-use"},
			{1, "python.lang.best-practice.unused-import", "medium", "src/utils.py:3", "unused-import"},
			{2, "python.lang.correctness.useless-comparison", "low", "src/config.py:10", "useless-comparison"},
			{3, "", "medium", "src/legacy.py:7", "Generic finding with no rule id."},
		}
		for _, tc := range tests {
			got := findings[tc.idx]
			if got.ID != tc.wantID {
				t.Errorf("findings[%d].ID = %q, want %q", tc.idx, got.ID, tc.wantID)
			}
			if string(got.Severity) != tc.wantSev {
				t.Errorf("findings[%d].Severity = %q, want %q", tc.idx, got.Severity, tc.wantSev)
			}
			if got.Location != tc.wantLoc {
				t.Errorf("findings[%d].Location = %q, want %q", tc.idx, got.Location, tc.wantLoc)
			}
			if got.Title != tc.wantTitle {
				t.Errorf("findings[%d].Title = %q, want %q", tc.idx, got.Title, tc.wantTitle)
			}
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = semgrepNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("unrecognized severity returns error", func(t *testing.T) {
		bad := `{"results":[{"check_id":"x.y","path":"a.py","start":{"line":1},"extra":{"message":"m","severity":"BOGUS"}}]}`
		_, _, err := semgrepNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for unrecognized severity, got nil")
		}
	})

	t.Run("empty check_id with single-line message uses whole message as title", func(t *testing.T) {
		in := `{"results":[{"check_id":"","path":"a.py","start":{"line":1},"extra":{"message":"single line message","severity":"INFO"}}]}`
		findings, _, err := semgrepNormalizer{}.Normalize(stringsReader(in))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1", len(findings))
		}
		if findings[0].Title != "single line message" {
			t.Errorf("Title = %q, want %q", findings[0].Title, "single line message")
		}
	})

	t.Run("no paths field yields zero passed count", func(t *testing.T) {
		findings, passedCount, err := semgrepNormalizer{}.Normalize(stringsReader(`{"results":[]}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passedCount != 0 {
			t.Errorf("passedCount = %d, want 0", passedCount)
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := semgrepNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("empty object missing results field returns error", func(t *testing.T) {
		_, _, err := semgrepNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing results field, got nil")
		}
	})

	t.Run("non-empty errors array returns error", func(t *testing.T) {
		bad := `{"results":[],"errors":[{"message":"timeout"}]}`
		_, _, err := semgrepNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for non-empty errors array, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing results field", func(t *testing.T) {
		f, err := os.Open("testdata/trivy/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = semgrepNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for trivy fixture fed to semgrep adapter, got nil")
		}
	})
}

func TestSemgrepNormalizer_CanonicalSeverities(t *testing.T) {
	f, err := os.Open("testdata/semgrep/canonical_severities.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	findings, _, err := semgrepNormalizer{}.Normalize(f)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("len(findings) = %d, want 4", len(findings))
	}

	want := []string{"critical", "high", "medium", "low"}
	for i, w := range want {
		if string(findings[i].Severity) != w {
			t.Errorf("findings[%d].Severity = %q, want %q", i, findings[i].Severity, w)
		}
	}
}

func TestSemgrepNormalizer_WarnLevelErrorsDoNotBlock(t *testing.T) {
	f, err := os.Open("testdata/semgrep/warn_errors.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	findings, _, err := semgrepNormalizer{}.Normalize(f)
	if err != nil {
		t.Fatalf("Normalize() error = %v, want nil (warn-level errors should not block)", err)
	}
	if len(findings) != 1 {
		t.Errorf("len(findings) = %d, want 1", len(findings))
	}
}

func TestSemgrepNormalizer_ErrorLevelErrorsBlock(t *testing.T) {
	f, err := os.Open("testdata/semgrep/error_level_errors.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	_, _, err = semgrepNormalizer{}.Normalize(f)
	if err == nil {
		t.Error("Normalize() expected error for error-level scan error, got nil")
	}
}

func TestSemgrepNormalizer_MissingLevelTreatedAsBlocking(t *testing.T) {
	bad := `{"results":[],"errors":[{"code":1,"message":"unknown failure"}]}`
	_, _, err := semgrepNormalizer{}.Normalize(stringsReader(bad))
	if err == nil {
		t.Error("Normalize() expected error for error entry with no level (fail-closed), got nil")
	}
}

// TestSemgrepNormalizer_ErrorLevelAllowlist locks in the fail-closed
// allowlist: only "warn", "warning", and "info" are non-blocking. Every
// other level - including ones that sound more severe than "error", like
// "fatal" or "critical", and any unrecognized value - blocks, rather than
// only "error" blocking and everything else passing through.
func TestSemgrepNormalizer_ErrorLevelAllowlist(t *testing.T) {
	nonBlocking := []string{"warn", "warning", "info", "WARN", "Info"}
	for _, level := range nonBlocking {
		input := fmt.Sprintf(`{"results":[],"errors":[{"level":%q,"message":"m"}]}`, level)
		_, _, err := semgrepNormalizer{}.Normalize(stringsReader(input))
		if err != nil {
			t.Errorf("level %q: unexpected error = %v, want nil (non-blocking)", level, err)
		}
	}

	blocking := []string{"error", "fatal", "critical", "unknown-level", ""}
	for _, level := range blocking {
		input := fmt.Sprintf(`{"results":[],"errors":[{"level":%q,"message":"m"}]}`, level)
		_, _, err := semgrepNormalizer{}.Normalize(stringsReader(input))
		if err == nil {
			t.Errorf("level %q: expected error (fail-closed, blocking), got nil", level)
		}
	}
}

func TestSemgrepNormalizer_DuplicateCaseVariantKeyRejected(t *testing.T) {
	input := `{"results":[],"RESULTS":[{"check_id":"x"}]}`
	_, _, err := semgrepNormalizer{}.Normalize(stringsReader(input))
	if err == nil {
		t.Error("Normalize() expected error for case-variant duplicate top-level key, got nil")
	}
}

func TestSemgrepNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("semgrep")
	if err != nil {
		t.Fatalf("Get(semgrep) error = %v", err)
	}
	if n.CheckType() != "sast" {
		t.Errorf("Get(semgrep).CheckType() = %q, want %q", n.CheckType(), "sast")
	}
}

func TestRun_SemgrepAdapter(t *testing.T) {
	t.Run("fails when an error-level finding is present", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("semgrep", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a high finding is present)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("semgrep", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}
