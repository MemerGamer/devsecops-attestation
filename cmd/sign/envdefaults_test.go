package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
)

// fakeLookup builds a lookup func over a fixed map, for injecting a fake
// environment into resolveEnvDefaults without touching process-wide state.
func fakeLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestResolveEnvDefaults(t *testing.T) {
	t.Run("no CI env vars set yields empty defaults", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(nil))
		if got.signerID != "" || got.logEntry != "" {
			t.Errorf("resolveEnvDefaults() = %+v, want zero value", got)
		}
	})

	t.Run("GitHub Actions env derives signer-id and log-entry", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(map[string]string{
			"GITHUB_SERVER_URL": "https://github.com",
			"GITHUB_REPOSITORY": "MemerGamer/devsecops-attestation",
			"GITHUB_WORKFLOW":   "devsecops-pipeline",
			"GITHUB_JOB":        "sast-scan",
			"GITHUB_RUN_ID":     "123456789",
		}))
		wantSignerID := "github.com:MemerGamer/devsecops-attestation:devsecops-pipeline:sast-scan"
		if got.signerID != wantSignerID {
			t.Errorf("signerID = %q, want %q", got.signerID, wantSignerID)
		}
		wantLogEntry := "https://github.com/MemerGamer/devsecops-attestation/actions/runs/123456789"
		if got.logEntry != wantLogEntry {
			t.Errorf("logEntry = %q, want %q", got.logEntry, wantLogEntry)
		}
	})

	t.Run("Forgejo env (same var names) is portable", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(map[string]string{
			"GITHUB_SERVER_URL": "https://forge.example.org",
			"GITHUB_REPOSITORY": "org/repo",
			"GITHUB_WORKFLOW":   "ci",
			"GITHUB_JOB":        "sca-scan",
			"GITHUB_RUN_ID":     "42",
		}))
		wantSignerID := "forge.example.org:org/repo:ci:sca-scan"
		if got.signerID != wantSignerID {
			t.Errorf("signerID = %q, want %q", got.signerID, wantSignerID)
		}
	})

	t.Run("missing run-id omits log-entry but still derives signer-id", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(map[string]string{
			"GITHUB_SERVER_URL": "https://github.com",
			"GITHUB_REPOSITORY": "org/repo",
			"GITHUB_WORKFLOW":   "ci",
			"GITHUB_JOB":        "job",
		}))
		if got.signerID == "" {
			t.Error("expected signerID to be derived even without GITHUB_RUN_ID")
		}
		if got.logEntry != "" {
			t.Errorf("logEntry = %q, want empty when GITHUB_RUN_ID is unset", got.logEntry)
		}
	})

	t.Run("partial env leaves signer-id empty rather than embedding empty segments", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(map[string]string{
			"GITHUB_JOB": "sast-scan",
		}))
		if got.signerID != "" {
			t.Errorf("signerID = %q, want empty when only some of the four vars are set", got.signerID)
		}
	})

	t.Run("three of four vars set still leaves signer-id empty", func(t *testing.T) {
		got := resolveEnvDefaults(fakeLookup(map[string]string{
			"GITHUB_SERVER_URL": "https://github.com",
			"GITHUB_REPOSITORY": "org/repo",
			"GITHUB_WORKFLOW":   "ci",
		}))
		if got.signerID != "" {
			t.Errorf("signerID = %q, want empty when GITHUB_JOB is unset", got.signerID)
		}
	})

	t.Run("stripScheme handles scheme-less and schemed URLs", func(t *testing.T) {
		if got := stripScheme("https://github.com"); got != "github.com" {
			t.Errorf("stripScheme(https) = %q, want github.com", got)
		}
		if got := stripScheme("http://forge.example.org"); got != "forge.example.org" {
			t.Errorf("stripScheme(http) = %q, want forge.example.org", got)
		}
		if got := stripScheme("github.com"); got != "github.com" {
			t.Errorf("stripScheme(no scheme) = %q, want github.com", got)
		}
	})
}

func TestRunSignEnvDefaultsIntegration(t *testing.T) {
	ctx := context.Background()

	t.Run("env vars populate signer-id and log-entry when flags are empty", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		t.Setenv("GITHUB_SERVER_URL", "https://github.com")
		t.Setenv("GITHUB_REPOSITORY", "org/repo")
		t.Setenv("GITHUB_WORKFLOW", "ci")
		t.Setenv("GITHUB_JOB", "sast-scan")
		t.Setenv("GITHUB_RUN_ID", "999")

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: "testdata/sast-result.json",
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			chain:      chainPath,
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].SignerID != "github.com:org/repo:ci:sast-scan" {
			t.Errorf("SignerID = %q, want derived from env", chain[0].SignerID)
		}
		if chain[0].LogEntry != "https://github.com/org/repo/actions/runs/999" {
			t.Errorf("LogEntry = %q, want derived from env", chain[0].LogEntry)
		}
	})

	t.Run("explicit flags take priority over env derivation", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		t.Setenv("GITHUB_SERVER_URL", "https://github.com")
		t.Setenv("GITHUB_REPOSITORY", "org/repo")
		t.Setenv("GITHUB_WORKFLOW", "ci")
		t.Setenv("GITHUB_JOB", "sast-scan")
		t.Setenv("GITHUB_RUN_ID", "999")

		err := runSign(ctx, signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: "testdata/sast-result.json",
			targetRef:  "abc123",
			subject:    "myapp",
			signingKey: privHex,
			signerID:   "explicit-signer",
			logEntry:   "explicit-log-entry",
			chain:      chainPath,
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].SignerID != "explicit-signer" {
			t.Errorf("SignerID = %q, want explicit-signer", chain[0].SignerID)
		}
		if chain[0].LogEntry != "explicit-log-entry" {
			t.Errorf("LogEntry = %q, want explicit-log-entry", chain[0].LogEntry)
		}
	})

	t.Run("--no-env-defaults disables derivation even when env vars are set", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		privHex, _ := generateTestKey(t)

		t.Setenv("GITHUB_SERVER_URL", "https://github.com")
		t.Setenv("GITHUB_REPOSITORY", "org/repo")
		t.Setenv("GITHUB_WORKFLOW", "ci")
		t.Setenv("GITHUB_JOB", "sast-scan")
		t.Setenv("GITHUB_RUN_ID", "999")

		err := runSign(ctx, signFlags{
			checkType:     "sast",
			tool:          "semgrep",
			resultFile:    "testdata/sast-result.json",
			targetRef:     "abc123",
			subject:       "myapp",
			signingKey:    privHex,
			chain:         chainPath,
			noEnvDefaults: true,
		})
		if err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if chain[0].SignerID != "" {
			t.Errorf("SignerID = %q, want empty with --no-env-defaults", chain[0].SignerID)
		}
		if chain[0].LogEntry != "" {
			t.Errorf("LogEntry = %q, want empty with --no-env-defaults", chain[0].LogEntry)
		}
	})
}
