// Command gate evaluates a verified attestation chain against a Rego policy
// and produces a deployment gate decision (allow / block).
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
	Use:   "gate",
	Short: "Evaluate an attestation chain against a deployment gate policy",
}

var evaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Run the gate policy against an attestation chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr, "gate evaluate: not yet implemented (Phase 3)")
		os.Exit(1)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(evaluateCmd)
}
