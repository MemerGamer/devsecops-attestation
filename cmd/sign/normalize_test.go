package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	semgrepFindingsFixture   = "../../pkg/normalize/testdata/semgrep/findings.json"
	semgrepCleanFixture      = "../../pkg/normalize/testdata/semgrep/clean.json"
	semgrepMalformedFixture  = "../../pkg/normalize/testdata/semgrep/malformed.json"
	gitleaksFindingsFixture  = "../../pkg/normalize/testdata/gitleaks/findings.json"
	gitleaksCleanFixture     = "../../pkg/normalize/testdata/gitleaks/clean.json"
	gitleaksMalformedFixture = "../../pkg/normalize/testdata/gitleaks/malformed.json"
)

func TestRunNormalize(t *testing.T) {
	t.Run("semgrep findings written to stdout", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := runNormalize(normalizeFlags{
				tool:   "semgrep",
				in:     semgrepFindingsFixture,
				failOn: "high",
			})
			if err != nil {
				t.Fatalf("runNormalize() error = %v", err)
			}
		})
		if !strings.Contains(out, `"findings"`) {
			t.Errorf("stdout = %q, want it to contain findings", out)
		}
		if !strings.Contains(out, `"passed": false`) {
			t.Errorf("stdout = %q, want passed:false since an ERROR finding is present", out)
		}
	})

	t.Run("semgrep findings written to --out file", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "result.json")

		err := runNormalize(normalizeFlags{
			tool:   "semgrep",
			in:     semgrepFindingsFixture,
			out:    outPath,
			failOn: "high",
		})
		if err != nil {
			t.Fatalf("runNormalize() error = %v", err)
		}

		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !strings.Contains(string(data), "dangerous-subprocess-use") {
			t.Errorf("output file missing expected finding, got %s", data)
		}
	})

	t.Run("semgrep clean report passes", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := runNormalize(normalizeFlags{
				tool:   "semgrep",
				in:     semgrepCleanFixture,
				failOn: "high",
			})
			if err != nil {
				t.Fatalf("runNormalize() error = %v", err)
			}
		})
		if !strings.Contains(out, `"passed": true`) {
			t.Errorf("stdout = %q, want passed:true for clean report", out)
		}
	})

	t.Run("gitleaks findings always critical and fail even with high fail-on default", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := runNormalize(normalizeFlags{
				tool:   "gitleaks",
				in:     gitleaksFindingsFixture,
				failOn: "high",
			})
			if err != nil {
				t.Fatalf("runNormalize() error = %v", err)
			}
		})
		if !strings.Contains(out, `"passed": false`) {
			t.Errorf("stdout = %q, want passed:false for gitleaks findings", out)
		}
		if !strings.Contains(out, "aws-access-token") {
			t.Errorf("stdout = %q, want it to contain the gitleaks rule id", out)
		}
	})

	t.Run("gitleaks clean report passes", func(t *testing.T) {
		out := captureStdout(t, func() {
			err := runNormalize(normalizeFlags{
				tool:   "gitleaks",
				in:     gitleaksCleanFixture,
				failOn: "high",
			})
			if err != nil {
				t.Fatalf("runNormalize() error = %v", err)
			}
		})
		if !strings.Contains(out, `"passed": true`) {
			t.Errorf("stdout = %q, want passed:true for clean gitleaks report", out)
		}
	})

	t.Run("reads from stdin when --in is -", func(t *testing.T) {
		data, err := os.ReadFile(semgrepCleanFixture)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		restoreStdin := setStdin(t, data)
		defer restoreStdin()

		out := captureStdout(t, func() {
			err := runNormalize(normalizeFlags{
				tool:   "semgrep",
				in:     "-",
				failOn: "high",
			})
			if err != nil {
				t.Fatalf("runNormalize() error = %v", err)
			}
		})
		if !strings.Contains(out, `"passed": true`) {
			t.Errorf("stdout = %q, want passed:true", out)
		}
	})

	t.Run("fails for unknown tool", func(t *testing.T) {
		err := runNormalize(normalizeFlags{
			tool:   "not-a-real-tool",
			in:     semgrepCleanFixture,
			failOn: "high",
		})
		if err == nil {
			t.Error("runNormalize() expected error for unknown tool, got nil")
		}
	})

	t.Run("fails for missing input file", func(t *testing.T) {
		dir := t.TempDir()
		err := runNormalize(normalizeFlags{
			tool:   "semgrep",
			in:     filepath.Join(dir, "nonexistent.json"),
			failOn: "high",
		})
		if err == nil {
			t.Error("runNormalize() expected error for missing input file, got nil")
		}
	})

	t.Run("fails for malformed semgrep report", func(t *testing.T) {
		err := runNormalize(normalizeFlags{
			tool:   "semgrep",
			in:     semgrepMalformedFixture,
			failOn: "high",
		})
		if err == nil {
			t.Error("runNormalize() expected error for malformed report, got nil")
		}
	})

	t.Run("fails for malformed gitleaks report", func(t *testing.T) {
		err := runNormalize(normalizeFlags{
			tool:   "gitleaks",
			in:     gitleaksMalformedFixture,
			failOn: "high",
		})
		if err == nil {
			t.Error("runNormalize() expected error for malformed report, got nil")
		}
	})

	t.Run("fails for invalid --fail-on", func(t *testing.T) {
		err := runNormalize(normalizeFlags{
			tool:   "semgrep",
			in:     semgrepCleanFixture,
			failOn: "not-a-severity",
		})
		if err == nil {
			t.Error("runNormalize() expected error for invalid --fail-on, got nil")
		}
	})

	t.Run("fails for unwritable --out path", func(t *testing.T) {
		dir := t.TempDir()
		roDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(roDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.Chmod(roDir, 0o444); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { os.Chmod(roDir, 0o755) }) //nolint

		err := runNormalize(normalizeFlags{
			tool:   "semgrep",
			in:     semgrepCleanFixture,
			out:    filepath.Join(roDir, "out.json"),
			failOn: "high",
		})
		if err == nil {
			t.Error("runNormalize() expected error for unwritable --out path, got nil")
		}
	})
}

// TestRunNormalizeViaCobraExecute exercises the cobra RunE closure for the
// normalize subcommand.
func TestRunNormalizeViaCobraExecute(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")

	rootCmd.SetArgs([]string{
		"normalize",
		"--tool=semgrep",
		"--in=" + semgrepCleanFixture,
		"--out=" + outPath,
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}

func TestRunTools(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runTools(); err != nil {
			t.Fatalf("runTools() error = %v", err)
		}
	})

	if !strings.Contains(out, "semgrep\tsast") {
		t.Errorf("tools output = %q, want it to list semgrep with check type sast", out)
	}
	if !strings.Contains(out, "gitleaks\tsecret") {
		t.Errorf("tools output = %q, want it to list gitleaks with check type secret", out)
	}
	if !strings.Contains(out, "generic\t-") {
		t.Errorf("tools output = %q, want the generic adapter to show '-' for check type", out)
	}
}

// TestRunToolsViaCobraExecute exercises the cobra RunE closure for the
// tools subcommand.
func TestRunToolsViaCobraExecute(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tools"})
		t.Cleanup(func() { rootCmd.SetArgs(nil) })
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("rootCmd.Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, "semgrep") {
		t.Errorf("tools output = %q, want it to list semgrep", out)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// whatever was written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return buf.String()
}

// setStdin redirects os.Stdin to a pipe fed with data, returning a restore
// function that must be called (typically via defer) to put os.Stdin back.
func setStdin(t *testing.T, data []byte) func() {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		w.Write(data)
		w.Close()
	}()
	os.Stdin = r
	return func() {
		os.Stdin = orig
	}
}
