package normalize

import (
	"os"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func TestMixAuditNormalizer_NameAndCheckType(t *testing.T) {
	n := mixAuditNormalizer{}
	if n.Name() != "mix-audit" {
		t.Errorf("Name() = %q, want %q", n.Name(), "mix-audit")
	}
	if n.CheckType() != "sca" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sca")
	}
}

func TestMixAuditNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := mixAuditNormalizer{}.Normalize(f)
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

	t.Run("findings report maps each vulnerability", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, _, err := mixAuditNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 4 {
			t.Fatalf("len(findings) = %d, want 4", len(findings))
		}

		if findings[0].ID != "CVE-2023-12345" {
			t.Errorf("findings[0].ID = %q, want %q", findings[0].ID, "CVE-2023-12345")
		}
		if findings[0].Severity != types.Severity("high") {
			t.Errorf("findings[0].Severity = %q, want high", findings[0].Severity)
		}
		if findings[0].Title != "Denial of service in Plug.Parsers.MULTIPART" {
			t.Errorf("findings[0].Title = %q", findings[0].Title)
		}
		if findings[0].Location != "mix.lock:phoenix@1.6.10" {
			t.Errorf("findings[0].Location = %q, want %q", findings[0].Location, "mix.lock:phoenix@1.6.10")
		}

		// No CVE, falls back to the advisory's own HSEC ID.
		if findings[1].ID != "HSEC-2022-0007" {
			t.Errorf("findings[1].ID = %q, want %q", findings[1].ID, "HSEC-2022-0007")
		}
		if findings[1].Severity != types.Severity("low") {
			t.Errorf("findings[1].Severity = %q, want low", findings[1].Severity)
		}

		// No severity or CVSS reported at all: falls back to high.
		if findings[2].ID != "HSEC-2021-0003" {
			t.Errorf("findings[2].ID = %q, want %q", findings[2].ID, "HSEC-2021-0003")
		}
		if findings[2].Severity != types.Severity("high") {
			t.Errorf("findings[2].Severity = %q, want high (no severity reported)", findings[2].Severity)
		}

		// CVSS vector present: takes priority over the reported "medium"
		// severity string and resolves via FromCVSS (this vector scores 9.8).
		if findings[3].ID != "CVE-2024-99999" {
			t.Errorf("findings[3].ID = %q, want %q", findings[3].ID, "CVE-2024-99999")
		}
		if findings[3].Severity != types.Severity("critical") {
			t.Errorf("findings[3].Severity = %q, want critical (CVSS overrides reported severity)", findings[3].Severity)
		}
	})

	t.Run("advisory with invalid severity string returns error", func(t *testing.T) {
		bad := `{"pass": false, "vulnerabilities": [{"advisory": {"id": "HSEC-X", "severity": "nonsense"}, "dependency": {"package": "p", "version": "1.0.0", "lockfile": "mix.lock"}}]}`
		_, _, err := mixAuditNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for invalid advisory severity, got nil")
		}
	})

	t.Run("advisory with malformed CVSS vector returns error", func(t *testing.T) {
		bad := `{"pass": false, "vulnerabilities": [{"advisory": {"id": "HSEC-X", "cvss": "not-a-vector"}, "dependency": {"package": "p", "version": "1.0.0", "lockfile": "mix.lock"}}]}`
		_, _, err := mixAuditNormalizer{}.Normalize(stringsReader(bad))
		if err == nil {
			t.Error("Normalize() expected error for malformed CVSS vector, got nil")
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = mixAuditNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := mixAuditNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("empty object missing pass field returns error", func(t *testing.T) {
		_, _, err := mixAuditNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing the pass field, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing the pass field", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = mixAuditNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for semgrep fixture fed to mix-audit adapter, got nil")
		}
	})
}

func TestMixAuditNormalizer_NormalizeWithPass(t *testing.T) {
	t.Run("carries through pass:false with no vulnerabilities", func(t *testing.T) {
		findings, _, toolPassed, err := mixAuditNormalizer{}.NormalizeWithPass(stringsReader(`{"pass": false, "vulnerabilities": []}`))
		if err != nil {
			t.Fatalf("NormalizeWithPass() error = %v", err)
		}
		if toolPassed {
			t.Error("toolPassed = true, want false")
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
	})

	t.Run("carries through pass:true", func(t *testing.T) {
		_, _, toolPassed, err := mixAuditNormalizer{}.NormalizeWithPass(stringsReader(`{"pass": true, "vulnerabilities": []}`))
		if err != nil {
			t.Fatalf("NormalizeWithPass() error = %v", err)
		}
		if !toolPassed {
			t.Error("toolPassed = false, want true")
		}
	})
}

// TestRun_MixAuditAdapter_ToolReportedPassIsHonored verifies the bug fix:
// mix_audit's pass:false must flow into Result.Passed even when no
// individual advisory meets the caller's --fail-on threshold.
func TestRun_MixAuditAdapter_ToolReportedPassIsHonored(t *testing.T) {
	result, err := Run("mix-audit", stringsReader(`{"pass": false, "vulnerabilities": []}`), SeverityCritical)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Passed {
		t.Error("result.Passed = true, want false (mix_audit self-reported pass:false)")
	}
}

func TestMixAuditID(t *testing.T) {
	tests := []struct {
		name string
		adv  mixAuditAdvisory
		want string
	}{
		{"prefers cve", mixAuditAdvisory{ID: "HSEC-1", CVE: "CVE-1"}, "CVE-1"},
		{"falls back to advisory id", mixAuditAdvisory{ID: "HSEC-1", CVE: ""}, "HSEC-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mixAuditID(tt.adv); got != tt.want {
				t.Errorf("mixAuditID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMixAuditSeverity(t *testing.T) {
	t.Run("uses reported severity string", func(t *testing.T) {
		sev, err := mixAuditSeverity(mixAuditAdvisory{Severity: "critical"})
		if err != nil {
			t.Fatalf("mixAuditSeverity() error = %v", err)
		}
		if sev != SeverityCritical {
			t.Errorf("sev = %v, want SeverityCritical", sev)
		}
	})

	t.Run("defaults to high with no severity reported", func(t *testing.T) {
		sev, err := mixAuditSeverity(mixAuditAdvisory{})
		if err != nil {
			t.Fatalf("mixAuditSeverity() error = %v", err)
		}
		if sev != SeverityHigh {
			t.Errorf("sev = %v, want SeverityHigh", sev)
		}
	})

	t.Run("invalid severity string returns error", func(t *testing.T) {
		_, err := mixAuditSeverity(mixAuditAdvisory{Severity: "nonsense"})
		if err == nil {
			t.Error("mixAuditSeverity() expected error, got nil")
		}
	})

	t.Run("CVSS vector takes priority over reported severity", func(t *testing.T) {
		sev, err := mixAuditSeverity(mixAuditAdvisory{
			Severity: "medium",
			CVSS:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		})
		if err != nil {
			t.Fatalf("mixAuditSeverity() error = %v", err)
		}
		if sev != SeverityCritical {
			t.Errorf("sev = %v, want SeverityCritical", sev)
		}
	})

	t.Run("malformed CVSS vector returns error", func(t *testing.T) {
		_, err := mixAuditSeverity(mixAuditAdvisory{CVSS: "not-a-vector"})
		if err == nil {
			t.Error("mixAuditSeverity() expected error for malformed CVSS vector, got nil")
		}
	})
}

func TestMixAuditNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("mix-audit")
	if err != nil {
		t.Fatalf("Get(mix-audit) error = %v", err)
	}
	if n.Name() != "mix-audit" {
		t.Errorf("Get(mix-audit).Name() = %q, want %q", n.Name(), "mix-audit")
	}
}

func TestRun_MixAuditAdapter(t *testing.T) {
	t.Run("fails when a high or above finding is present", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("mix-audit", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a high finding is present)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("mix-audit", f, SeverityLow)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}
