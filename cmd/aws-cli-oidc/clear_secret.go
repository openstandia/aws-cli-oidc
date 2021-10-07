package main

import (
	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
)

var clearSecretCmd = &cobra.Command{
	Use:   "clear-secret",
	Short: "Clear OS secret store that saves AWS credentials",
	Long:  `Clear OS secret store that saves AWS credentials.`,
	Run:   clearSecret,
}

func init() {
	rootCmd.AddCommand(clearSecretCmd)
}

func clearSecret(cmd *cobra.Command, args []string) {
	if err := lib.Clear(); err != nil {
		lib.Writeln("Failed to clear the secret store")
		lib.Exit(err)
	}
	lib.Write("The secret store has been cleared")
}
