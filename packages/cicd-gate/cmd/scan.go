package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run compliance policies against infrastructure-as-code files",
	Long: `Scan runs the configured Rego policies against infrastructure-as-code files
in the specified directory (or current directory if not specified).
It wraps conftest to evaluate policies and provides remediation hints.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		socratic, _ := cmd.Flags().GetBool("socratic")
		policyPath, _ := cmd.Flags().GetString("policy")

		conftestArgs := []string{"test", target}
		if policyPath != "" {
			conftestArgs = append(conftestArgs, "--policy", policyPath)
		}
		if socratic {
			conftestArgs = append(conftestArgs, "--output", "stdout")
		}

		c := exec.Command("conftest", conftestArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := c.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("conftest failed: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("socratic", "s", false, "Verbose remediation hints with ISM mapping")
	scanCmd.Flags().StringP("policy", "p", "", "Path to policy directory (default: ./policies)")
}
