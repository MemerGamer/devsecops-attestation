package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
)

// TestSignSubcommand exercises `attest sign ...`, the exact invocation the
// CI workflow uses. Before the sign subcommand was added, cobra rejected
// "sign" as an unrecognized command once the normalize/tools subcommands
// existed; this test guards against that regression.
func TestSignSubcommand(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	privHex, _ := generateTestKey(t)

	rootCmd.SetArgs([]string{
		"sign",
		"--check-type=sast", "--tool=semgrep",
		"--result=testdata/sast-result.json",
		"--target-ref=abc123", "--subject=myapp",
		"--signing-key=" + privHex,
		"--chain=" + chainPath,
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() with sign subcommand error = %v", err)
	}

	chain, err := attestation.LoadChain(chainPath)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
	if chain[0].Result.CheckType != "sast" {
		t.Errorf("CheckType = %q, want sast", chain[0].Result.CheckType)
	}
}

// TestBareRootFormStillWorks exercises the bare-root invocation form (no
// "sign" token) to confirm it still works unchanged for backward
// compatibility alongside the new sign subcommand.
func TestBareRootFormStillWorks(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	privHex, _ := generateTestKey(t)

	rootCmd.SetArgs([]string{
		"--check-type=sca", "--tool=trivy",
		"--result=testdata/sast-result.json",
		"--target-ref=abc123", "--subject=myapp",
		"--signing-key=" + privHex,
		"--chain=" + chainPath,
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() bare root form error = %v", err)
	}

	chain, err := attestation.LoadChain(chainPath)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}
	if chain[0].Result.CheckType != "sca" {
		t.Errorf("CheckType = %q, want sca", chain[0].Result.CheckType)
	}
}

// TestSignSubcommandMirrorsWorkflowFlags mirrors the exact flag set used by
// .github/workflows/devsecops-pipeline.yml's `./bin/attest sign` steps,
// including --signer-id and --log-entry, to prove the fix end to end.
func TestSignSubcommandMirrorsWorkflowFlags(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	privHex, _ := generateTestKey(t)

	rootCmd.SetArgs([]string{
		"sign",
		"--check-type=sast",
		"--tool=semgrep",
		"--tool-version=1.99.0",
		"--result=testdata/sast-result.json",
		"--target-ref=abc123def456",
		"--subject=devsecops-attestation",
		"--signing-key=" + privHex,
		"--signer-id=github.com:org/repo:ci:sast-scan",
		"--log-entry=https://github.com/org/repo/actions/runs/123",
		"--chain=" + chainPath,
		"--no-env-defaults",
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}
}

// TestRunSign_RejectsNonCanonicalSeverityWithoutToolFormat exercises the
// non-normalized --result path: a hand-authored result file with a
// non-canonical severity spelling must be rejected rather than silently
// signed.
func TestRunSign_RejectsNonCanonicalSeverityWithoutToolFormat(t *testing.T) {
	ctx := context.Background()

	t.Run("uppercase severity is rejected", func(t *testing.T) {
		dir := t.TempDir()
		badResult := filepath.Join(dir, "bad-severity.json")
		if err := os.WriteFile(badResult, []byte(`{"passed": false, "passed_count": 0, "findings": [{"id": "x", "severity": "HIGH", "title": "t"}]}`), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: badResult,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Fatal("runSign() expected error for non-canonical severity, got nil")
		}
	})

	t.Run("synonym severity is rejected (not silently accepted like ParseSeverity would)", func(t *testing.T) {
		dir := t.TempDir()
		badResult := filepath.Join(dir, "bad-severity.json")
		if err := os.WriteFile(badResult, []byte(`{"passed": false, "passed_count": 0, "findings": [{"id": "x", "severity": "moderate", "title": "t"}]}`), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: badResult,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err == nil {
			t.Fatal("runSign() expected error for non-canonical (synonym) severity, got nil")
		}
	})

	t.Run("canonical severities are accepted", func(t *testing.T) {
		dir := t.TempDir()
		goodResult := filepath.Join(dir, "good-severity.json")
		body := `{"passed": false, "passed_count": 0, "findings": [
			{"id": "a", "severity": "info", "title": "t"},
			{"id": "b", "severity": "low", "title": "t"},
			{"id": "c", "severity": "medium", "title": "t"},
			{"id": "d", "severity": "high", "title": "t"},
			{"id": "e", "severity": "critical", "title": "t"}
		]}`
		if err := os.WriteFile(goodResult, []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		privHex, _ := generateTestKey(t)

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: goodResult,
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      filepath.Join(dir, "chain.json"),
		})
		if err != nil {
			t.Fatalf("runSign() unexpected error for canonical severities: %v", err)
		}
	})
}

// TestFailOnDefaultIsCritical documents and locks in the fail-on default
// change: both `sign --fail-on` and `normalize --fail-on` must default to
// "critical" to match the gate's default --fail-on-severity, rather than
// the previous "high" default which made the signer-side threshold
// independently blocking.
func TestFailOnDefaultIsCritical(t *testing.T) {
	if got := rootCmd.Flags().Lookup("fail-on").DefValue; got != "critical" {
		t.Errorf("root --fail-on default = %q, want critical", got)
	}
	if got := signCmd.Flags().Lookup("fail-on").DefValue; got != "critical" {
		t.Errorf("sign --fail-on default = %q, want critical", got)
	}
	if got := normalizeCmd.Flags().Lookup("fail-on").DefValue; got != "critical" {
		t.Errorf("normalize --fail-on default = %q, want critical", got)
	}
}
