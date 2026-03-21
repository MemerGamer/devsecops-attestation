// Command keygen generates an Ed25519 key pair for signing attestations.
// Store the private key hex in GitHub Actions secrets as ATTESTATION_SIGNING_KEY.
// Distribute the public key hex as ATTESTATION_PUBLIC_KEY for verification.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 key pair for signing attestations",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr, "keygen: not yet implemented (Phase 3)")
		os.Exit(1)
		return nil
	},
}
