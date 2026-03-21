// Command sign creates a signed attestation for a security check result
// and appends it to an attestation chain file.
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
	Use:   "sign",
	Short: "Sign a security check result and append it to the attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr, "sign: not yet implemented (Phase 3)")
		os.Exit(1)
		return nil
	},
}
