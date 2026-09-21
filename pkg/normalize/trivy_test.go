package normalize

import (
	"os"
	"testing"
)

func TestTrivyNormalizer_NameAndCheckType(t *testing.T) {
	n := trivyNormalizer{}
	if n.Name() != "trivy" {
		t.Errorf("Name() = %q, want %q", n.Name(), "trivy")
	}
	if n.CheckType() != "sca" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sca")
	}
}

func TestTrivyNormalizer_Normalize(t *testing.T) {
	t.Run("clean report (null vulnerabilities) has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/trivy/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := trivyNormalizer{}.Normalize(f)
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

	t.Run("null Results yields no findings", func(t *testing.T) {
		findings, _, err := trivyNormalizer{}.Normalize(stringsReader(`{"SchemaVersion":2,"Results":null}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
	})

	t.Run("findings report maps vulnerabilities, misconfigurations and secrets", func(t *testing.T) {
		f, err := os.Open("testdata/trivy/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, _, err := trivyNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 7 {
			t.Fatalf("len(findings) = %d, want 7", len(findings))
		}

		tests := []struct {
			idx       int
			wantID    string
			wantSev   string
			wantLoc   string
			wantTitle string
		}{
			{0, "CVE-2020-26235", "medium", "Cargo.lock:time@0.1.45", "Segmentation fault in time"},
			{1, "CVE-2023-99999", "critical", "Cargo.lock:example@1.0.0", "example 1.0.0"},
			{2, "CVE-2023-88888", "high", "Cargo.lock:another@2.1.0", "Denial of service in another crate"},
			{3, "CVE-2022-77777", "low", "Cargo.lock:leftpad@3.0.0", "Minor information disclosure"},
			{4, "CVE-2021-66666", "low", "Cargo.lock:obscure@0.5.0", "Unclassified issue"},
			{5, "AVD-DS-0002", "high", "Dockerfile:1", "Image user should not be 'root'"},
			{6, "aws-access-key-id", "critical", "src/config.rs:12", "AWS Access Key ID"},
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
		f, err := os.Open("testdata/trivy/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = trivyNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("unrecognized vulnerability severity returns error", func(t *testing.T) {
		bad := `{"SchemaVersion":2,"Results":[{"Target":"x","Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"BOGUS"}]}]}`
		_, _, err := trivyNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for unrecognized severity, got nil")
		}
	})

	t.Run("unrecognized misconfiguration severity returns error", func(t *testing.T) {
		bad := `{"SchemaVersion":2,"Results":[{"Target":"x","Misconfigurations":[{"ID":"M-1","Severity":"BOGUS"}]}]}`
		_, _, err := trivyNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for unrecognized severity, got nil")
		}
	})

	t.Run("unrecognized secret severity returns error", func(t *testing.T) {
		bad := `{"SchemaVersion":2,"Results":[{"Target":"x","Secrets":[{"RuleID":"S-1","Severity":"BOGUS"}]}]}`
		_, _, err := trivyNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for unrecognized severity, got nil")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := trivyNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("empty object missing SchemaVersion returns error", func(t *testing.T) {
		_, _, err := trivyNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing SchemaVersion, got nil")
		}
	})

	t.Run("unsupported SchemaVersion returns error", func(t *testing.T) {
		_, _, err := trivyNormalizer{}.Normalize(stringsReader(`{"SchemaVersion":1,"Results":[]}`))
		if err == nil {
			t.Error("Normalize() expected error for unsupported SchemaVersion, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing SchemaVersion", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = trivyNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for semgrep fixture fed to trivy adapter, got nil")
		}
	})
}

func TestTrivyNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("trivy")
	if err != nil {
		t.Fatalf("Get(trivy) error = %v", err)
	}
	if n.CheckType() != "sca" {
		t.Errorf("Get(trivy).CheckType() = %q, want %q", n.CheckType(), "sca")
	}
}

func TestRun_TrivyAdapter(t *testing.T) {
	t.Run("fails when a critical vulnerability is present", func(t *testing.T) {
		f, err := os.Open("testdata/trivy/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("trivy", f, SeverityCritical)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a critical finding is present)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/trivy/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("trivy", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}
