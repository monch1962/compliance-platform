package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of cicd-gate",
	Long:  `Print the version number of cicd-gate.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cicd-gate %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
