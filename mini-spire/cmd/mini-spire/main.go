package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:          "mini-spire",
		Short:        "mini-spire CLI",
		SilenceUsage: true,
	}

	cmd.AddCommand(
		devSpireCmd(),
	)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
