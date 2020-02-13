package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	input "github.com/natsukagami/go-input"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive setup of aws-cli-oidc",
	Long:  `Interactive setup of aws-cli-oidc. Will prompt you for OIDC provider URL and other settings.`,
	Run:   setup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func setup(cmd *cobra.Command, args []string) {
	runSetup()
}

func runSetup() {
	providerName, _ := ui.Ask("OIDC provider name:", &input.Options{
		Required: true,
		Loop:     true,
	})
	server, _ := ui.Ask("OIDC provider metadata URL (https://your-oidc-provider/.well-known/openid-configuration):", &input.Options{
		Required: true,
		Loop:     true,
	})
	additionalQuery, _ := ui.Ask("Additional query for OIDC authentication request (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	successfulRedirectURL, _ := ui.Ask("Successful redirect URL (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	failureRedirectURL, _ := ui.Ask("Failure redirect URL (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	clientID, _ := ui.Ask("Client ID which is registered in the OIDC provider:", &input.Options{
		Required: true,
		Loop:     true,
	})
	clientSecret, _ := ui.Ask("Client secret which is registered in the OIDC provider (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	answerFedType, _ := ui.Ask(fmt.Sprintf("Choose type of AWS federation [%s]:", AWS_FEDERATION_TYPE_OIDC), &input.Options{
		Default:  AWS_FEDERATION_TYPE_OIDC,
		Required: false,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != AWS_FEDERATION_TYPE_OIDC {
				return errors.New(fmt.Sprintf("Input must be '%s'", AWS_FEDERATION_TYPE_OIDC))
			}
			return nil
		},
	})
	maxSessionDurationSeconds, _ := ui.Ask("The max session duration, in seconds, of the role session [900-43200] (Default: 3600):", &input.Options{
		Default:  "3600",
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			i, err := strconv.ParseInt(s, 10, 64)
			if err != nil || i < 900 || i > 43200 {
				return errors.New(fmt.Sprintf("Input must be 900-43200"))
			}
			return nil
		},
	})
	defaultIAMRoleArn, _ := ui.Ask("The default IAM Role ARN when you have multiple roles, as arn:aws:iam::<account-id>:role/<role-name> (Default: none):", &input.Options{
		Default:  "",
		Required: false,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s == "" {
				return nil
			}
			arn := strings.Split(s, ":")
			if len(arn) == 6 {
				if arn[0] == "arn" && arn[1] == "aws" && arn[2] == "iam" && arn[3] == "" && strings.HasPrefix(arn[5], "role/") {
					return nil
				}
			}
			return errors.New(fmt.Sprintf("Input must be IAM Role ARN"))
		},
	})

	config := map[string]string{}

	config[OIDC_PROVIDER_METADATA_URL] = server
	config[OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY] = additionalQuery
	config[SUCCESSFUL_REDIRECT_URL] = successfulRedirectURL
	config[FAILURE_REDIRECT_URL] = failureRedirectURL
	config[CLIENT_ID] = clientID
	config[CLIENT_SECRET] = clientSecret
	config[AWS_FEDERATION_TYPE] = answerFedType
	config[MAX_SESSION_DURATION_SECONDS] = maxSessionDurationSeconds
	config[DEFAULT_IAM_ROLE_ARN] = defaultIAMRoleArn

	if answerFedType == AWS_FEDERATION_TYPE_OIDC {
		oidcSetup(config)
	}

	viper.Set(providerName, config)

	os.MkdirAll(ConfigPath(), 0700)
	configPath := ConfigPath() + "/config.yaml"
	viper.SetConfigFile(configPath)
	err := viper.WriteConfig()

	if err != nil {
		Writeln("Failed to write %s", configPath)
		Exit(err)
	}

	Writeln("Saved %s", configPath)
}

func oidcSetup(config map[string]string) {
	awsRole, _ := ui.Ask("AWS federation role (arn:aws:iam::<Account ID>:role/<Role Name>):", &input.Options{
		Required: true,
		Loop:     true,
	})
	awsRoleSessionName, _ := ui.Ask("AWS federation roleSessionName:", &input.Options{
		Required: true,
		Loop:     true,
	})
	config[AWS_FEDERATION_ROLE] = awsRole
	config[AWS_FEDERATION_ROLE_SESSION_NAME] = awsRoleSessionName
}
