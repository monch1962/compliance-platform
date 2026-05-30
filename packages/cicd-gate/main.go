package main

import (
	"os"

	"github.com/monch1962/compliance-platform/packages/cicd-gate/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}