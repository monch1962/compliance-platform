package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a .cicd-gate.yaml configuration file",
	Long: `Init creates a .cicd-gate.yaml file in the current directory with
sensible defaults for policy paths, severity levels, and pass/fail thresholds.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		template := `# cicd-gate configuration
policy_path: "./policies"
severity:
  critical: "deny"
  high: "deny"
  medium: "warn"
  low: "info"
output: "stdout"
socratic: false
`

		if _, err := os.Stat(".cicd-gate.yaml"); err == nil {
			return fmt.Errorf(".cicd-gate.yaml already exists")
		}

		if err := os.WriteFile(".cicd-gate.yaml", []byte(template), 0644); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}

		fmt.Println("Created .cicd-gate.yaml")
		fmt.Println("Edit this file to configure which policies to run and severity levels.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
	
	// Ensure viper looks for .cicd-gate.yaml
	viper.SetConfigName(".cicd-gate")
	viper.SetConfigType("yaml")
}
