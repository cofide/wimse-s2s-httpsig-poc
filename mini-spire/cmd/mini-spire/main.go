package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd *cobra.Command

func main() {
	cmd := &cobra.Command{
		Use:          "mini-spire",
		Short:        "mini-spire CLI",
		SilenceUsage: true,
	}

	cmd.AddCommand(
		devSpireCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
