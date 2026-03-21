package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
)

func TestRunKeygen(t *testing.T) {
	t.Run("writes two key files in temp dir", func(t *testing.T) {
		dir := t.TempDir()
		err := runKeygen(keygenFlags{out: dir, force: false})
		if err != nil {
			t.Fatalf("runKeygen() error = %v", err)
		}

		privPath := filepath.Join(dir, "private.hex")
		pubPath := filepath.Join(dir, "public.hex")

		if _, err := os.Stat(privPath); os.IsNotExist(err) {
			t.Error("private.hex was not created")
		}
		if _, err := os.Stat(pubPath); os.IsNotExist(err) {
			t.Error("public.hex was not created")
		}
	})

	t.Run("public key hex is 64 characters (32 bytes)", func(t *testing.T) {
		dir := t.TempDir()
		if err := runKeygen(keygenFlags{out: dir}); err != nil {
			t.Fatalf("runKeygen() error = %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "public.hex"))
		if err != nil {
			t.Fatalf("reading public.hex: %v", err)
		}
		pubHex := string(data)
		if len(pubHex) != 64 {
			t.Errorf("public key hex length = %d, want 64", len(pubHex))
		}
		b, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatalf("public.hex is not valid hex: %v", err)
		}
		if len(b) != ed25519.PublicKeySize {
			t.Errorf("public key byte length = %d, want %d", len(b), ed25519.PublicKeySize)
		}
	})

	t.Run("private key hex is 128 characters (64 bytes)", func(t *testing.T) {
		dir := t.TempDir()
		if err := runKeygen(keygenFlags{out: dir}); err != nil {
			t.Fatalf("runKeygen() error = %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "private.hex"))
		if err != nil {
			t.Fatalf("reading private.hex: %v", err)
		}
		privHex := string(data)
		if len(privHex) != 128 {
			t.Errorf("private key hex length = %d, want 128", len(privHex))
		}
		b, err := hex.DecodeString(privHex)
		if err != nil {
			t.Fatalf("private.hex is not valid hex: %v", err)
		}
		if len(b) != ed25519.PrivateKeySize {
			t.Errorf("private key byte length = %d, want %d", len(b), ed25519.PrivateKeySize)
		}
	})

	t.Run("round-trip: load private key and compare public key", func(t *testing.T) {
		dir := t.TempDir()
		if err := runKeygen(keygenFlags{out: dir}); err != nil {
			t.Fatalf("runKeygen() error = %v", err)
		}

		privData, err := os.ReadFile(filepath.Join(dir, "private.hex"))
		if err != nil {
			t.Fatalf("reading private.hex: %v", err)
		}
		pubData, err := os.ReadFile(filepath.Join(dir, "public.hex"))
		if err != nil {
			t.Fatalf("reading public.hex: %v", err)
		}

		privBytes, _ := hex.DecodeString(string(privData))
		pubBytes, _ := hex.DecodeString(string(pubData))

		// Ed25519 private key embeds public key in last 32 bytes.
		embeddedPub := privBytes[32:]
		if string(embeddedPub) != string(pubBytes) {
			t.Error("public key in private.hex does not match public.hex")
		}

		// Load as KeyPair and verify it works.
		kp, err := crypto.KeyPairFromBytes(pubBytes, privBytes)
		if err != nil {
			t.Fatalf("KeyPairFromBytes() error = %v", err)
		}
		if len(kp.PublicKey) != ed25519.PublicKeySize {
			t.Errorf("loaded PublicKey size = %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
		}
	})

	t.Run("fails if out path is a file not a directory", func(t *testing.T) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(filePath, []byte("content"), 0o644); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Attempt to use the file as output directory.
		err := runKeygen(keygenFlags{out: filepath.Join(filePath, "subdir")})
		if err == nil {
			t.Error("runKeygen() expected error for invalid out path, got nil")
		}
	})

	t.Run("fails if key files exist and --force not set", func(t *testing.T) {
		dir := t.TempDir()
		if err := runKeygen(keygenFlags{out: dir}); err != nil {
			t.Fatalf("first runKeygen() error = %v", err)
		}
		err := runKeygen(keygenFlags{out: dir, force: false})
		if err == nil {
			t.Error("second runKeygen() without --force should fail, got nil")
		}
	})

	t.Run("succeeds with --force when files exist", func(t *testing.T) {
		dir := t.TempDir()
		if err := runKeygen(keygenFlags{out: dir}); err != nil {
			t.Fatalf("first runKeygen() error = %v", err)
		}
		if err := runKeygen(keygenFlags{out: dir, force: true}); err != nil {
			t.Errorf("second runKeygen() with --force error = %v", err)
		}
	})
}
