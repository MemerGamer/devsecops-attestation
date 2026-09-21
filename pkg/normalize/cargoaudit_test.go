package normalize

import (
	"os"
	"testing"
)

func TestCargoAuditNormalizer_NameAndCheckType(t *testing.T) {
	n := cargoAuditNormalizer{}
	if n.Name() != "cargo-audit" {
		t.Errorf("Name() = %q, want %q", n.Name(), "cargo-audit")
	}
	if n.CheckType() != "sca" {
		t.Errorf("CheckType() = %q, want %q", n.CheckType(), "sca")
	}
}

func TestCargoAuditNormalizer_Normalize(t *testing.T) {
	t.Run("clean report has no findings and full passed count", func(t *testing.T) {
		f, err := os.Open("testdata/cargoaudit/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := cargoAuditNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("len(findings) = %d, want 0", len(findings))
		}
		if passedCount != 184 {
			t.Errorf("passedCount = %d, want 184", passedCount)
		}
	})

	t.Run("findings report maps vulnerabilities and warnings", func(t *testing.T) {
		f, err := os.Open("testdata/cargoaudit/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		findings, passedCount, err := cargoAuditNormalizer{}.Normalize(f)
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 5 {
			t.Fatalf("len(findings) = %d, want 5", len(findings))
		}

		// 184 dependencies, 2 vulnerable -> 182 passed.
		if passedCount != 182 {
			t.Errorf("passedCount = %d, want 182", passedCount)
		}

		byID := make(map[string]struct {
			severity string
			location string
			title    string
		})
		for _, f := range findings {
			byID[f.ID] = struct {
				severity string
				location string
				title    string
			}{string(f.Severity), f.Location, f.Title}
		}

		timeVuln, ok := byID["RUSTSEC-2020-0071"]
		if !ok {
			t.Fatal("missing finding for RUSTSEC-2020-0071")
		}
		wantScore, err := cvssBaseScore("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
		if err != nil {
			t.Fatalf("cvssBaseScore: %v", err)
		}
		wantSev := FromCVSS(wantScore).String()
		if timeVuln.severity != wantSev {
			t.Errorf("time vuln severity = %q, want %q (score %v)", timeVuln.severity, wantSev, wantScore)
		}
		if timeVuln.location != "Cargo.lock:time@0.1.44" {
			t.Errorf("time vuln location = %q, want %q", timeVuln.location, "Cargo.lock:time@0.1.44")
		}

		noCVSSVuln, ok := byID["RUSTSEC-2024-0011"]
		if !ok {
			t.Fatal("missing finding for RUSTSEC-2024-0011")
		}
		if noCVSSVuln.severity != "high" {
			t.Errorf("no-CVSS vuln severity = %q, want high", noCVSSVuln.severity)
		}

		unmaintained, ok := byID["RUSTSEC-2021-0139"]
		if !ok {
			t.Fatal("missing finding for RUSTSEC-2021-0139 (unmaintained warning)")
		}
		if unmaintained.severity != "low" {
			t.Errorf("unmaintained warning severity = %q, want low", unmaintained.severity)
		}

		yanked, ok := byID["yanked:example-yanked@0.3.0"]
		if !ok {
			t.Fatal("missing finding for yanked entry without advisory")
		}
		if yanked.severity != "low" {
			t.Errorf("yanked warning severity = %q, want low", yanked.severity)
		}
		if yanked.location != "Cargo.lock:example-yanked@0.3.0" {
			t.Errorf("yanked location = %q, want %q", yanked.location, "Cargo.lock:example-yanked@0.3.0")
		}

		unsound, ok := byID["RUSTSEC-2023-0055"]
		if !ok {
			t.Fatal("missing finding for unsound warning")
		}
		if unsound.severity != "medium" {
			t.Errorf("unsound warning severity = %q, want medium", unsound.severity)
		}
	})

	t.Run("malformed report returns error", func(t *testing.T) {
		f, err := os.Open("testdata/cargoaudit/malformed.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = cargoAuditNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for malformed JSON, got nil")
		}
	})

	t.Run("read error is propagated", func(t *testing.T) {
		_, _, err := cargoAuditNormalizer{}.Normalize(errReader{})
		if err == nil {
			t.Error("Normalize() expected error from failing reader, got nil")
		}
	})

	t.Run("passed count floors at zero when vulnerable count exceeds dependency count", func(t *testing.T) {
		input := `{
			"database": {"advisory-count": 1},
			"lockfile": {"dependency-count": 1},
			"vulnerabilities": {"found": true, "count": 2, "list": [
				{"advisory": {"id": "A-1", "title": "t", "cvss": null}, "package": {"name": "a", "version": "1.0.0"}},
				{"advisory": {"id": "A-2", "title": "t", "cvss": null}, "package": {"name": "b", "version": "1.0.0"}}
			]},
			"warnings": {"unmaintained": [], "yanked": [], "unsound": []}
		}`
		_, passedCount, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if passedCount != 0 {
			t.Errorf("passedCount = %d, want 0 (floored)", passedCount)
		}
	})

	t.Run("unparseable cvss vector fails closed to critical severity", func(t *testing.T) {
		// The tool did supply a CVSS vector, just one this adapter's parser
		// cannot interpret (including CVSS 4.0 vectors), so it must not be
		// silently treated the same as "no score at all" (high): fail
		// closed to critical instead.
		input := `{
			"database": {"advisory-count": 1},
			"lockfile": {"dependency-count": 1},
			"vulnerabilities": {"found": true, "count": 1, "list": [
				{"advisory": {"id": "A-1", "title": "t", "cvss": "not-a-real-vector"}, "package": {"name": "a", "version": "1.0.0"}}
			]},
			"warnings": {"unmaintained": [], "yanked": [], "unsound": []}
		}`
		findings, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1", len(findings))
		}
		if string(findings[0].Severity) != "critical" {
			t.Errorf("severity = %q, want critical", findings[0].Severity)
		}
	})

	t.Run("CVSS 4.0 vector (unsupported by this adapter's parser) fails closed to critical severity", func(t *testing.T) {
		input := `{
			"database": {"advisory-count": 1},
			"lockfile": {"dependency-count": 1},
			"vulnerabilities": {"found": true, "count": 1, "list": [
				{"advisory": {"id": "A-1", "title": "t", "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, "package": {"name": "a", "version": "1.0.0"}}
			]},
			"warnings": {"unmaintained": [], "yanked": [], "unsound": []}
		}`
		findings, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
		if err != nil {
			t.Fatalf("Normalize() error = %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1", len(findings))
		}
		if string(findings[0].Severity) != "critical" {
			t.Errorf("severity = %q, want critical", findings[0].Severity)
		}
	})

	t.Run("empty object missing database and lockfile fields returns error", func(t *testing.T) {
		_, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(`{}`))
		if err == nil {
			t.Error("Normalize() expected error for report missing database/lockfile fields, got nil")
		}
	})

	t.Run("another tool's fixture is rejected for missing schema markers", func(t *testing.T) {
		f, err := os.Open("testdata/semgrep/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		_, _, err = cargoAuditNormalizer{}.Normalize(f)
		if err == nil {
			t.Error("Normalize() expected error for semgrep fixture fed to cargo-audit adapter, got nil")
		}
	})

	t.Run("vulnerabilities.count mismatched with list length returns error", func(t *testing.T) {
		input := `{
			"database": {"advisory-count": 1},
			"lockfile": {"dependency-count": 1},
			"vulnerabilities": {"found": true, "count": 2, "list": [
				{"advisory": {"id": "A-1", "title": "t"}, "package": {"name": "a", "version": "1.0.0"}}
			]},
			"warnings": {"unmaintained": [], "yanked": [], "unsound": []}
		}`
		_, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
		if err == nil {
			t.Error("Normalize() expected error for count/list mismatch, got nil")
		}
	})

	t.Run("count greater than zero with empty list returns error", func(t *testing.T) {
		input := `{
			"database": {"advisory-count": 1},
			"lockfile": {"dependency-count": 1},
			"vulnerabilities": {"found": false, "count": 1, "list": []},
			"warnings": {"unmaintained": [], "yanked": [], "unsound": []}
		}`
		_, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
		if err == nil {
			t.Error("Normalize() expected error for count > 0 with empty list, got nil")
		}
	})
}

func TestCargoAuditNormalizer_RegisteredInDefaultRegistry(t *testing.T) {
	n, err := Get("cargo-audit")
	if err != nil {
		t.Fatalf("Get(cargo-audit) error = %v", err)
	}
	if n.Name() != "cargo-audit" {
		t.Errorf("Get(cargo-audit).Name() = %q, want %q", n.Name(), "cargo-audit")
	}
	if n.CheckType() != "sca" {
		t.Errorf("Get(cargo-audit).CheckType() = %q, want %q", n.CheckType(), "sca")
	}
}

func TestRun_CargoAuditAdapter(t *testing.T) {
	t.Run("fails when a high or critical vulnerability is present", func(t *testing.T) {
		f, err := os.Open("testdata/cargoaudit/findings.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("cargo-audit", f, SeverityHigh)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if result.Passed {
			t.Error("result.Passed = true, want false (high-severity vulnerabilities present)")
		}
	})

	t.Run("passes on a clean report", func(t *testing.T) {
		f, err := os.Open("testdata/cargoaudit/clean.json")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()

		result, err := Run("cargo-audit", f, SeverityCritical)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed {
			t.Error("result.Passed = false, want true (no findings)")
		}
	})
}

func TestCargoAuditNormalizer_DuplicateCaseVariantKeyRejected(t *testing.T) {
	input := `{"database":{},"Database":{},"lockfile":{"dependency-count":1},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{"unmaintained":[],"yanked":[],"unsound":[]}}`
	_, _, err := cargoAuditNormalizer{}.Normalize(stringsReader(input))
	if err == nil {
		t.Error("Normalize() expected error for case-variant duplicate top-level key, got nil")
	}
}
