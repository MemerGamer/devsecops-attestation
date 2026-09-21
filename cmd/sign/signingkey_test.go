package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/attestation"
)

// TestResolveSigningKey exercises resolveSigningKey's source-priority and
// mutual-exclusion rules directly, without touching process-wide state.
func TestResolveSigningKey(t *testing.T) {
	t.Run("signing-key flag alone is used", func(t *testing.T) {
		got, err := resolveSigningKey(signFlags{signingKey: "deadbeef"}, fakeLookup(nil))
		if err != nil {
			t.Fatalf("resolveSigningKey() error = %v", err)
		}
		if got != "deadbeef" {
			t.Errorf("resolveSigningKey() = %q, want deadbeef", got)
		}
	})

	t.Run("signing-key-file alone is used and whitespace is trimmed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(path, []byte("  cafef00d\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		got, err := resolveSigningKey(signFlags{signingKeyFile: path}, fakeLookup(nil))
		if err != nil {
			t.Fatalf("resolveSigningKey() error = %v", err)
		}
		if got != "cafef00d" {
			t.Errorf("resolveSigningKey() = %q, want cafef00d", got)
		}
	})

	t.Run("ATTEST_SIGNING_KEY env alone is used when neither flag is set", func(t *testing.T) {
		got, err := resolveSigningKey(signFlags{}, fakeLookup(map[string]string{
			"ATTEST_SIGNING_KEY": "feedface",
		}))
		if err != nil {
			t.Fatalf("resolveSigningKey() error = %v", err)
		}
		if got != "feedface" {
			t.Errorf("resolveSigningKey() = %q, want feedface", got)
		}
	})

	t.Run("both signing-key and signing-key-file set is an error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(path, []byte("cafef00d"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := resolveSigningKey(signFlags{signingKey: "deadbeef", signingKeyFile: path}, fakeLookup(nil))
		if err == nil {
			t.Fatal("resolveSigningKey() expected error when both --signing-key and --signing-key-file are set, got nil")
		}
	})

	t.Run("no source set is an error", func(t *testing.T) {
		_, err := resolveSigningKey(signFlags{}, fakeLookup(nil))
		if err == nil {
			t.Fatal("resolveSigningKey() expected error when no signing key source is set, got nil")
		}
	})

	t.Run("signing-key flag takes priority over ATTEST_SIGNING_KEY env", func(t *testing.T) {
		got, err := resolveSigningKey(signFlags{signingKey: "deadbeef"}, fakeLookup(map[string]string{
			"ATTEST_SIGNING_KEY": "feedface",
		}))
		if err != nil {
			t.Fatalf("resolveSigningKey() error = %v", err)
		}
		if got != "deadbeef" {
			t.Errorf("resolveSigningKey() = %q, want deadbeef (flag priority)", got)
		}
	})

	t.Run("signing-key-file takes priority over ATTEST_SIGNING_KEY env", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(path, []byte("cafef00d"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		got, err := resolveSigningKey(signFlags{signingKeyFile: path}, fakeLookup(map[string]string{
			"ATTEST_SIGNING_KEY": "feedface",
		}))
		if err != nil {
			t.Fatalf("resolveSigningKey() error = %v", err)
		}
		if got != "cafef00d" {
			t.Errorf("resolveSigningKey() = %q, want cafef00d (file priority over env)", got)
		}
	})

	t.Run("nonexistent signing-key-file is an error", func(t *testing.T) {
		_, err := resolveSigningKey(signFlags{signingKeyFile: filepath.Join(t.TempDir(), "missing.hex")}, fakeLookup(nil))
		if err == nil {
			t.Fatal("resolveSigningKey() expected error for nonexistent --signing-key-file, got nil")
		}
	})

	t.Run("empty signing-key-file contents is an error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := resolveSigningKey(signFlags{signingKeyFile: path}, fakeLookup(nil))
		if err == nil {
			t.Fatal("resolveSigningKey() expected error for empty --signing-key-file contents, got nil")
		}
	})
}

// TestRunSignSigningKeySources exercises resolveSigningKey's integration
// into runSign end to end, through each source.
func TestRunSignSigningKeySources(t *testing.T) {
	ctx := context.Background()
	privHex, _ := generateTestKey(t)

	baseFlags := func(chainPath string) signFlags {
		return signFlags{
			checkType:  "sast",
			tool:       "semgrep",
			resultFile: "testdata/sast-result.json",
			targetRef:  "abc123",
			subject:    "myapp",
			chain:      chainPath,
		}
	}

	t.Run("via --signing-key-file", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		keyPath := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(keyPath, []byte(privHex+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		f := baseFlags(chainPath)
		f.signingKeyFile = keyPath

		if err := runSign(ctx, f); err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if len(chain) != 1 {
			t.Fatalf("chain length = %d, want 1", len(chain))
		}
	})

	t.Run("via ATTEST_SIGNING_KEY env", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")

		t.Setenv("ATTEST_SIGNING_KEY", privHex)

		f := baseFlags(chainPath)

		if err := runSign(ctx, f); err != nil {
			t.Fatalf("runSign() error = %v", err)
		}

		chain, err := attestation.LoadChain(chainPath)
		if err != nil {
			t.Fatalf("LoadChain() error = %v", err)
		}
		if len(chain) != 1 {
			t.Fatalf("chain length = %d, want 1", len(chain))
		}
	})

	t.Run("both --signing-key and --signing-key-file set fails before writing anything", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")
		keyPath := filepath.Join(dir, "key.hex")
		if err := os.WriteFile(keyPath, []byte(privHex), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		f := baseFlags(chainPath)
		f.signingKey = privHex
		f.signingKeyFile = keyPath

		if err := runSign(ctx, f); err == nil {
			t.Fatal("runSign() expected error when both --signing-key and --signing-key-file are set, got nil")
		}
		if _, err := os.Stat(chainPath); !os.IsNotExist(err) {
			t.Errorf("chain file should not have been written, stat error = %v", err)
		}
	})

	t.Run("no signing key source set fails", func(t *testing.T) {
		dir := t.TempDir()
		chainPath := filepath.Join(dir, "chain.json")

		f := baseFlags(chainPath)

		if err := runSign(ctx, f); err == nil {
			t.Fatal("runSign() expected error when no signing key source is set, got nil")
		}
	})
}

// TestSignSubcommandSigningKeyFile exercises `attest sign --signing-key-file
// ...` through rootCmd.Execute(), covering the cobra RunE path.
func TestSignSubcommandSigningKeyFile(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	keyPath := filepath.Join(dir, "key.hex")
	privHex, _ := generateTestKey(t)
	if err := os.WriteFile(keyPath, []byte(privHex), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// The package-level `flags` var is shared across every test in this
	// package and cobra only overwrites flags actually passed on the next
	// command line, so start from a clean slate: otherwise a signing-key
	// (or signing-key-file) value left over from a previous test could
	// silently satisfy --signing-key-file here, or vice versa.
	flags.signingKey = ""
	flags.signingKeyFile = ""
	rootCmd.SetArgs([]string{
		"sign",
		"--check-type=sast", "--tool=semgrep",
		"--result=testdata/sast-result.json",
		"--target-ref=abc123", "--subject=myapp",
		"--signing-key-file=" + keyPath,
		"--chain=" + chainPath,
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		flags.signingKeyFile = ""
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() with --signing-key-file error = %v", err)
	}

	chain, err := attestation.LoadChain(chainPath)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
}

// TestSignSubcommandNoSigningKeySource exercises `attest sign` via
// rootCmd.Execute() with no signing key source at all, which cobra no
// longer rejects at flag-parse time (signing-key is not MarkFlagRequired
// any more, since two other sources exist); the error must come from
// resolveSigningKey/runSign instead.
func TestSignSubcommandNoSigningKeySource(t *testing.T) {
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")

	flags.signingKey = ""
	flags.signingKeyFile = ""
	rootCmd.SetArgs([]string{
		"sign",
		"--check-type=sast", "--tool=semgrep",
		"--result=testdata/sast-result.json",
		"--target-ref=abc123", "--subject=myapp",
		"--chain=" + chainPath,
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		flags.signingKey = ""
		flags.signingKeyFile = ""
	})

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("rootCmd.Execute() expected error with no signing key source, got nil")
	}
}
