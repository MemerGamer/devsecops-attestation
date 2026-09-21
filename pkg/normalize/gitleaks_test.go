package normalize

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGitleaksNormalizer_NameAndCheckType(t *testing.T) {
	n := gitleaksNormalizer{}
	if n.Name() != "gitleaks" {
		t.Errorf("Name() = %q, want %q", n.Name(), "gitleaks")
	}
	if n.CheckType() != "secret" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "secret")
	}
}

func TestGitleaksNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := gitleaksNormalizer{}.Normalize(f)
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

	t.Run("empty file returns error (cannot distinguish clean from crashed scan)", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/empty.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = gitleaksNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for empty gitleaks report file, got nil")
		}
	})

	t.Run("whitespace-only input returns error", func(t *testing.T) {
		_, _, err := gitleaksNormalizer{}.Normalize(stringsReader("   \n\t  "))
		if err == nil {
			t.Error("Normalize() expected error for whitespace-only gitleaks report, got nil")
		}
	})

	t.Run("findings report maps every finding to critical", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, _, err := gitleaksNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 2 {
			t.Fatalf("len(findings) = %d, want 2", len(findings))
		}

		for _, finding := range findings {
			if string(finding.Severity) != "critical" {
				t.Errorf("finding %q severity = %q, want critical", finding.ID, finding.Severity)
			}
		}

		first := findings[0]
		if first.ID != "3f2c1a9b8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b:deploy/terraform.tfvars:aws-access-token:42" {
			t.Errorf("first.ID = %q, want fingerprint value", first.ID)
		}
		if first.Title != "aws-access-token" {
			t.Errorf("first.Title = %q, want %q", first.Title, "aws-access-token")
		}
		if first.Description != "AWS Access Key" {
			t.Errorf("first.Description = %q, want %q", first.Description, "AWS Access Key")
		}
		if first.Location != "deploy/terraform.tfvars:42" {
			t.Errorf("first.Location = %q, want %q", first.Location, "deploy/terraform.tfvars:42")
		}

		second := findings[1]
		if second.ID != "generic-api-key:config/settings.py:7" {
			t.Errorf("second.ID = %q, want fallback id built from RuleID:File:StartLine", second.ID)
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = gitleaksNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := gitleaksNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("empty JSON object is rejected (not an array)", func(t *testing.T) {
		_, _, err := gitleaksNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for a JSON object instead of an array, got nil")
		}
	})

	t.Run("another tool's fixture is rejected as not an array", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = gitleaksNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for semgrep fixture fed to gitleaks adapter, got nil")
		}
	})

	t.Run("secret and match values never appear in output", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, _, err := gitleaksNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}

		secrets := []string{
			"AKIAIOSFODNN7EXAMPLE",
			"sk_live_51H8qYt0000000000000000",
		}

		data, err := json.Marshal(findings)
		if err != nil {
			t.Fatalf("json.Marshal(findings) error = %v", err)
		}
		marshaled := string(data)

		for _, secret := range secrets {
			if strings.Contains(marshaled, secret) {
				t.Errorf("marshaled findings leak secret value %q: %s", secret, marshaled)
			}
		}
	})
}

func TestGitleaksNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("gitleaks")
	if err != nil {
		t.Fatalf("Get(gitleaks) error = %v", err)
	}
	if n.Name() != "gitleaks" {
		t.Errorf("Get(gitleaks).Name() = %q, want %q", n.Name(), "gitleaks")
	}
	if n.CheckType() != "secret" {
		t.Errorf("Get(gitleaks).CheckType() = %q, want %q", n.CheckType(), "secret")
	}
}

func TestRun_GitleaksAdapter(t *testing.T) {
	t.Run("fails when a secret is found (critical always meets high threshold)", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("gitleaks", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (secrets found)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/gitleaks/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("gitleaks", f, SeverityCritical)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}
