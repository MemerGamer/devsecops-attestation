// Command verify loads an attestation chain and verifies all signatures
// and chain linkage, reporting per-attestation results.
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
	Use:   "verify",
	Short: "Verify the signature and chain integrity of an attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr, "verify: not yet implemented (Phase 3)")
		os.Exit(1)
		return nil
	},
}
