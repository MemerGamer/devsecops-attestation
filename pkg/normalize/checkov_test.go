package normalize

import (
	"os"
	"testing"
)

func TestCheckovNormalizer_NameAndCheckType(t *testing.T) {
	n := checkovNormalizer{}
	if n.Name() != "checkov" {
		t.Errorf("Name() = %q, want %q", n.Name(), "checkov")
	}
	if n.CheckType() != "config" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "config")
	}
}

func TestCheckovNormalizer_Normalize(t *testing.T) {
	t.Run("clean single-framework report has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := checkovNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passedCount != 2 {
			t.Errorf("passedCount = %d, want 2", passedCount)
		}
	})

	t.Run("multi-framework array report maps severities, ids and locations", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := checkovNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 3 {
			t.Fatalf("len(findings) = %d, want 3", len(findings))
		}
		if passedCount != 1 {
			t.Errorf("passedCount = %d, want 1", passedCount)
		}

		tests := []struct {
			idx     int
			wantID  string
			wantSev string
			wantLoc string
		}{
			{0, "CKV_AWS_3", "high", "/main.tf:10"},
			{1, "CKV_AWS_4", "medium", "/network.tf:1"},
			{2, "CKV_DOCKER_2", "low", "/Dockerfile:1"},
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
		}
	})

	t.Run("empty-scan bare summary object yields no findings", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/empty_scan.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := checkovNormalizer{}.Normalize(f)
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

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = checkovNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("malformed multi-framework array returns error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(`[{"check_type":`))
		if err == nil {
			t.Error("Normalize() expected error for malformed array JSON, got nil")
		}
	})

	t.Run("leading whitespace before array is still detected as an array", func(t *testing.T) {
		findings, _, err := checkovNormalizer{}.Normalize(stringsReader("  \n [] "))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
	})

	t.Run("all-whitespace input returns a parse error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader("   "))
		if err == nil {
			t.Error("Normalize() expected error for whitespace-only input, got nil")
		}
	})

	t.Run("empty-scan object with wrong field type returns error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(`{"checkov_version": "3.2.0", "passed": "not-a-number"}`))
		if err == nil {
			t.Error("Normalize() expected error for malformed empty-scan object, got nil")
		}
	})

	t.Run("bare object missing checkov_version and resource_count returns error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(`{"passed": 0}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing checkov schema markers, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing schema markers", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = checkovNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for semgrep fixture fed to checkov adapter, got nil")
		}
	})

	t.Run("empty-scan object with parsing_errors > 0 and resources scanned returns error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(`{"checkov_version": "3.2.0", "parsing_errors": 2, "resource_count": 5}`))
		if err == nil {
			t.Error("Normalize() expected error for empty-scan report with parsing errors and scanned resources, got nil")
		}
	})

	t.Run("empty-scan object with parsing_errors > 0 but zero resources is ignored", func(t *testing.T) {
		findings, passed, err := checkovNormalizer{}.Normalize(stringsReader(`{"checkov_version": "3.2.0", "parsing_errors": 2, "resource_count": 0}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v, want nil (parsing errors on zero-resource framework should be ignored)", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passed != 0 {
			t.Errorf("passed = %d, want 0", passed)
		}
	})

	t.Run("single-framework report with parsing_errors > 0 and checks reported returns error", func(t *testing.T) {
		bad := `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":1,"parsing_errors":1}}`
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for report with parsing errors and passed checks, got nil")
		}
	})

	t.Run("single-framework report with parsing_errors > 0 but no resources scanned or checks reported is ignored", func(t *testing.T) {
		// This mirrors a real checkov scenario: a framework such as
		// terraform_plan attempts to parse files that turn out not to
		// belong to it (arbitrary .json files), records parsing_errors,
		// but finds zero resources and reports zero passed/failed checks.
		ok := `{"check_type":"terraform_plan","results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":0,"failed":0,"parsing_errors":3,"resource_count":0}}`
		findings, _, err := checkovNormalizer{}.Normalize(stringsReader(ok))
		if err != nil {
			t.Fatalf("Normalize() error = %v, want nil (parsing errors on zero-resource framework should be ignored)", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
	})

	t.Run("multi-framework report ignores parsing errors on empty framework but still fails on a framework with resources", func(t *testing.T) {
		bad := `[
			{"check_type":"terraform_plan","results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":0,"failed":0,"parsing_errors":2,"resource_count":0}},
			{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":3,"failed":0,"parsing_errors":1,"resource_count":3}}
		]`
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error: second framework has parsing errors and scanned resources")
		}
	})

	t.Run("single-framework object with wrong results type returns error", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(`{"results": "not-an-object"}`))
		if err == nil {
			t.Error("Normalize() expected error for malformed results field, got nil")
		}
	})

	t.Run("unrecognized severity string returns error", func(t *testing.T) {
		bad := `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_X","severity":"BOGUS"}]},"summary":{"passed":0}}`
		_, _, err := checkovNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for unrecognized severity, got nil")
		}
	})

	t.Run("empty failed_checks and passed_checks yields empty non-nil findings", func(t *testing.T) {
		findings, _, err := checkovNormalizer{}.Normalize(stringsReader(`{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":0}}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if findings == nil {
			t.Error("findings should be a non-nil empty slice")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := checkovNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})
}

func TestCheckovNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("checkov")
	if err != nil {
		t.Fatalf("Get(checkov) error = %v", err)
	}
	if n.CheckType() != "config" {
		t.Errorf("Get(checkov).CheckType() = %q, want %q", n.CheckType(), "config")
	}
}

func TestRun_CheckovAdapter(t *testing.T) {
	t.Run("fails when a high-severity failed check is present", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("checkov", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a high finding is present)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/checkov/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("checkov", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}
