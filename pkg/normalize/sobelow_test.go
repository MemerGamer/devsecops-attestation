package normalize

import (
	"os"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

func TestSobelowNormalizer_NameAndCheckType(t *testing.T) {
	n := sobelowNormalizer{}
	if n.Name() != "sobelow" {
		t.Errorf("Name() = %q, want %q", n.Name(), "sobelow")
	}
	if n.CheckType() != "sast" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sast")
	}
}

func TestSobelowNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/sobelow/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := sobelowNormalizer{}.Normalize(f)
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

	t.Run("findings report maps each confidence bucket", func(t *testing.T) {
		f, err := os.Open("testdata/sobelow/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, _, err := sobelowNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 3 {
			t.Fatalf("len(findings) = %d, want 3", len(findings))
		}

		want := []types.Finding{
			{
				ID:       "sql-injection:lib/myapp_web/controllers/user_controller.ex:42",
				Severity: types.Severity("high"),
				Title:    "SQL injection",
				Location: "lib/myapp_web/controllers/user_controller.ex:42",
			},
			{
				ID:       "xss:lib/myapp_web/templates/page/index.html.eex:10",
				Severity: types.Severity("medium"),
				Title:    "XSS",
				Location: "lib/myapp_web/templates/page/index.html.eex:10",
			},
			{
				ID:       "config-secrets:config/config.exs:5",
				Severity: types.Severity("low"),
				Title:    "Config secrets",
				Location: "config/config.exs:5",
			},
		}

		for i, w := range want {
			if findings[i] != w {
				t.Errorf("findings[%d] = %+v, want %+v", i, findings[i], w)
			}
		}
	})

	t.Run("missing confidence buckets are treated as empty", func(t *testing.T) {
		findings, _, err := sobelowNormalizer{}.Normalize(stringsReader(`{"sobelow_version":"0.13.0","total_findings":0,"findings":{}}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
	})

	t.Run("partial buckets are handled independently", func(t *testing.T) {
		findings, _, err := sobelowNormalizer{}.Normalize(stringsReader(`{
			"sobelow_version": "0.13.0",
			"total_findings": 1,
			"findings": {
				"high_confidence": [{"type": "XSS", "file": "a.ex", "line": 1}]
			}
		}`))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1", len(findings))
		}
		if findings[0].Severity != types.Severity("high") {
			t.Errorf("Severity = %q, want high", findings[0].Severity)
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/sobelow/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = sobelowNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := sobelowNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("empty object missing sobelow_version returns error", func(t *testing.T) {
		_, _, err := sobelowNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing sobelow_version, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing sobelow_version", func(t *testing.T) {
		f, err := os.Open("testdata/mixaudit/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = sobelowNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for mix-audit fixture fed to sobelow adapter, got nil")
		}
	})
}

func TestSobelowSlug(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"SQL injection", "sql-injection"},
		{"XSS", "xss"},
		{"  Config   secrets  ", "config-secrets"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := sobelowSlug(tt.in); got != tt.want {
			t.Errorf("sobelowSlug(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSobelowNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("sobelow")
	if err != nil {
		t.Fatalf("Get(sobelow) error = %v", err)
	}
	if n.Name() != "sobelow" {
		t.Errorf("Get(sobelow).Name() = %q, want %q", n.Name(), "sobelow")
	}
}

func TestRun_SobelowAdapter(t *testing.T) {
	t.Run("fails when a high confidence finding is present", func(t *testing.T) {
		f, err := os.Open("testdata/sobelow/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("sobelow", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (a high finding is present)")
		}
		if len(result.Findings) != 3 {
			t.Errorf("len(result.Findings) = %d, want 3", len(result.Findings))
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/sobelow/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("sobelow", f, SeverityLow)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}

func TestSobelowNormalizer_DuplicateCaseVariantKeyRejected(t *testing.T) {
	input := `{"sobelow_version":"0.13.0","Sobelow_version":"0.13.0","total_findings":0,"findings":{"high_confidence":[],"medium_confidence":[],"low_confidence":[]}}`
	_, _, err := sobelowNormalizer{}.Normalize(stringsReader(input))
	if err == nil {
		t.Error("Normalize() expected error for case-variant duplicate top-level key, got nil")
	}
}
