package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
)

func TestRunSignWithToolFormat(t *testing.T) {
	ctx := context.Background()

	t.Run("semgrep tool-format defaults tool and check-type and normalizes inline", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "semgrep",
			resultFile: semgrepFindingsFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
			failOn:     "high",
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].Result.CheckType != "sast" {
			t.Errorf("CheckType = %q, want sast (defaulted from semgrep adapter)", chain[0].Result.CheckType)
		}
		if chain[0].Result.Tool != "semgrep" {
			t.Errorf("Tool = %q, want semgrep (defaulted from adapter name)", chain[0].Result.Tool)
		}
		if chain[0].Result.Passed {
			t.Error("Passed = true, want false since findings.json has an ERROR-severity finding")
		}
		if len(chain[0].Result.Findings) == 0 {
			t.Error("expected findings to be populated from inline normalization")
		}
	})

	t.Run("gitleaks tool-format defaults check-type to secret", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "gitleaks",
			resultFile: gitleaksFindingsFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
			failOn:     "high",
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].Result.CheckType != "secret" {
			t.Errorf("CheckType = %q, want secret", chain[0].Result.CheckType)
		}
	})

	t.Run("explicit --tool and --check-type override adapter defaults", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "semgrep",
			tool:       "custom-semgrep-wrapper",
			checkType:  "dast",
			resultFile: semgrepCleanFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
			failOn:     "high",
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].Result.CheckType != "dast" {
			t.Errorf("CheckType = %q, want dast (explicit override)", chain[0].Result.CheckType)
		}
		if chain[0].Result.Tool != "custom-semgrep-wrapper" {
			t.Errorf("Tool = %q, want custom-semgrep-wrapper (explicit override)", chain[0].Result.Tool)
		}
	})

	t.Run("generic adapter without --check-type fails with clear error", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "generic",
			resultFile: semgrepCleanFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
			failOn:     "high",
		})
		if err == nil {
			t.Fatal("runSign() expected error for generic adapter without --check-type, got nil")
		}
	})

	t.Run("unknown --tool-format fails", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "not-a-real-adapter",
			resultFile: semgrepCleanFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
			failOn:     "high",
		})
		if err == nil {
			t.Fatal("runSign() expected error for unknown --tool-format, got nil")
		}
	})

	t.Run("malformed raw report with tool-format fails", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "semgrep",
			resultFile: semgrepMalformedFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
			failOn:     "high",
		})
		if err == nil {
			t.Fatal("runSign() expected error for malformed raw report, got nil")
		}
	})

	t.Run("invalid --fail-on with tool-format fails", func(t *testing.T) {
		dir := t.TempDir()
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			toolFormat: "semgrep",
			resultFile: semgrepCleanFixture,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
			failOn:     "not-a-severity",
		})
		if err == nil {
			t.Fatal("runSign() expected error for invalid --fail-on, got nil")
		}
	})
}

func TestResolveToolAndCheckType(t *testing.T) {
	t.Run("no tool-format requires both check-type and tool", func(t *testing.T) {
		f := &signFlags{}
		if err := resolveToolAndCheckType(f); err == nil {
			t.Error("expected error when neither check-type nor tool is set")
		}

		f = &signFlags{checkType: "sast"}
		if err := resolveToolAndCheckType(f); err == nil {
			t.Error("expected error when tool is not set")
		}

		f = &signFlags{tool: "semgrep"}
		if err := resolveToolAndCheckType(f); err == nil {
			t.Error("expected error when check-type is not set")
		}

		f = &signFlags{checkType: "sast", tool: "semgrep"}
		if err := resolveToolAndCheckType(f); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestRunSignViaCobraExecuteWithToolFormat exercises the cobra RunE closure
// with --tool-format set and both --tool and --check-type omitted, covering
// the manual flag validation from the top-level command path.
func TestRunSignViaCobraExecuteWithToolFormat(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	privHex, _ := generateTestKey(t)

	rootCmd.SetArgs([]string{
		"--tool-format=semgrep",
		"--result=" + semgrepCleanFixture,
		"--target-ref=abc123", "--subject=myapp",
		"--signing-key=" + privHex,
		"--chain=" + chainPath,
		"--no-env-defaults",
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}

// TestRootCmdVersion exercises the --version flag wiring.
func TestRootCmdVersion(t *testing.T) {
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"--version"})
		t.Cleanup(func() { rootCmd.SetArgs(nil) })
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("rootCmd.Execute() error = %v", err)
		}
	})
	if out == "" {
		t.Error("expected --version to print output")
	}
}
