package main

import (
	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
)

var getCredCmd = &cobra.Command{
	Use:   "get-cred <OIDC provider name>",
	Short: "Get AWS credentials and out to stdout",
	Long:  `Get AWS credentials and out to stdout through your OIDC provider authentication.`,
	Run:   getCred,
}

func init() {
	getCredCmd.Flags().StringP("provider", "p", "", "OIDC provider name")
	getCredCmd.Flags().StringP("role", "r", "", "Override default assume role ARN")
	getCredCmd.Flags().Int64P("max-duration", "d", 0, "Override default max session duration, in seconds, of the role session [900-43200]")
	getCredCmd.Flags().BoolP("use-secret", "s", false, "Store AWS credentials into OS secret store, then load it without re-authentication")
	getCredCmd.Flags().BoolP("json", "j", false, "Print the credential as JSON format")
	rootCmd.AddCommand(getCredCmd)
}

func getCred(cmd *cobra.Command, args []string) {
	providerName, _ := cmd.Flags().GetString("provider")
	if providerName == "" {
		lib.Writeln("The OIDC provider name is required")
		lib.Exit(nil)
	}

	roleArn, _ := cmd.Flags().GetString("role")
	maxDurationSeconds, _ := cmd.Flags().GetInt64("max-duration")
	useSecret, _ := cmd.Flags().GetBool("use-secret")
	asJson, _ := cmd.Flags().GetBool("json")

	client, err := lib.CheckInstalled(providerName)
	if err != nil {
		lib.Writeln("Failed to login OIDC provider")
		lib.Exit(err)
	}

	lib.Authenticate(client, roleArn, maxDurationSeconds, useSecret, asJson)
}
