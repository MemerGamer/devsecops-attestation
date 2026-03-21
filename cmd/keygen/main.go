// Command keygen generates an Ed25519 key pair for signing attestations.
// Store the private key hex in GitHub Actions secrets as ATTESTATION_SIGNING_KEY.
// Distribute the public key hex as ATTESTATION_PUBLIC_KEY for verification.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type keygenFlags struct {
	out   string
	force bool
}

var flags keygenFlags

var rootCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 key pair for signing attestations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeygen(flags)
	},
}

func init() {
	rootCmd.Flags().StringVar(&flags.out, "out", ".", "directory to write key files into")
	rootCmd.Flags().BoolVar(&flags.force, "force", false, "overwrite existing key files")
}

func runKeygen(f keygenFlags) error {
	privPath := filepath.Join(f.out, "private.hex")
	pubPath := filepath.Join(f.out, "public.hex")

	if !f.force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("key file already exists: %s (use --force to overwrite)", p)
			}
		}
	}

	if err := os.MkdirAll(f.out, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	privHex := hex.EncodeToString([]byte(kp.PrivateKey))
	pubHex := hex.EncodeToString([]byte(kp.PublicKey))

	if err := os.WriteFile(privPath, []byte(privHex), 0o600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubHex), 0o644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	fmt.Printf("Public key:  %s\n", pubHex)
	fmt.Printf("Private key written to: %s (keep secret)\n", privPath)
	fmt.Printf("Public key written to:  %s\n", pubPath)
	return nil
}
