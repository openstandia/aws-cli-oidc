package main

import (
	"github.com/openstandia/aws-cli-oidc/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "aws-cli-oidc",
	Short: "CLI tool for retrieving AWS temporary credentials using OIDC provider",
	Long:  `CLI tool for retrieving AWS temporary credentials using OIDC provider`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		lib.Writeln(err.Error())
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetConfigFile(lib.ConfigPath() + "/config.yaml")

	if err := viper.ReadInConfig(); err == nil {
		lib.Writeln("Using config file: %s", viper.ConfigFileUsed())
	}

	lib.IsTraceEnabled = false // TODO: configuable
}
