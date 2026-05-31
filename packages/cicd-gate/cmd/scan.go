package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

const legalHeader = `CI/CD Gate — Compliance Posture Monitor
Frameworks: ISM | E8 | SOCI
Tier: L1 (Machine-Verified) | L2 (Evidence-Assisted) | L3 (Process-Mapped) | L4 (Advisory)

IMPORTANT: This tool monitors compliance posture.
It does NOT certify compliance. See cicd-gate init for full disclaimer.

`

const legalFooter = `
---
Legal: Compliance posture monitoring — not a certification.
        Consult a qualified assessor for formal audit or certification.
`

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run compliance policies against infrastructure-as-code files",
	Long: `Scan runs the configured Rego policies against infrastructure-as-code files
in the specified directory (or current directory if not specified).
It wraps conftest to evaluate policies and provides remediation hints.

Each violation includes:
  - Rule ID (e.g., K8S-SEC-001)
  - Framework mapping (ISM, E8, SOCI) embedded in the message
  - Verification tier (L1-L4) embedded in the message
  - Remediation hint (in Socratic mode)`,
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

		c := exec.Command("conftest", conftestArgs...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if socratic {
			fmt.Print(legalHeader)
		}

		if err := c.Run(); err != nil {
			if socratic {
				fmt.Print(legalFooter)
			}
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("conftest failed: %w", err)
		}

		if socratic {
			fmt.Print(legalFooter)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("socratic", "s", false, "Verbose output with legal disclaimer header/footer (framework IDs and tier labels embedded in violation messages)")
	scanCmd.Flags().StringP("policy", "p", "", "Path to policy directory (default: ./policies)")
}
