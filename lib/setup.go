package lib

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	input "github.com/natsukagami/go-input"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func RunSetup(ui *input.UI) {
	if ui == nil {
		ui = &input.UI{
			Writer: os.Stdout,
			Reader: os.Stdin,
		}
	}

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
	clientAuthCert, _ := ui.Ask("A PEM encoded certificate file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	var clientAuthKey string
	var clientAuthCA string
	if clientAuthCert != "" {
		clientAuthKey, _ = ui.Ask("A PEM encoded private key file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
		clientAuthCA, _ = ui.Ask("A PEM encoded CA's certificate file which is required to access the OIDC provider with MTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
	}
	insecureSkipVerify, _ := ui.Ask("Insecure mode for HTTPS access (Default: false):", &input.Options{
		Default:  "false",
		Required: false,
		ValidateFunc: func(s string) error {
			if strings.ToLower(s) != "false" || strings.ToLower(s) != "true" {
				return errors.New(fmt.Sprintf("Input must be true or false"))
			}
			return nil
		},
	})
	answerFedType, _ := ui.Ask(fmt.Sprintf("Choose type of AWS federation [%s/%s]:", AWS_FEDERATION_TYPE_OIDC, AWS_FEDERATION_TYPE_SAML2), &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != AWS_FEDERATION_TYPE_SAML2 && s != AWS_FEDERATION_TYPE_OIDC {
				return errors.New(fmt.Sprintf("Input must be '%s' or '%s'", AWS_FEDERATION_TYPE_OIDC, AWS_FEDERATION_TYPE_SAML2))
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
	config[CLIENT_AUTH_CERT] = clientAuthCert
	config[CLIENT_AUTH_KEY] = clientAuthKey
	config[CLIENT_AUTH_CA] = clientAuthCA
	config[INSECURE_SKIP_VERIFY] = insecureSkipVerify
	config[AWS_FEDERATION_TYPE] = answerFedType
	config[MAX_SESSION_DURATION_SECONDS] = maxSessionDurationSeconds
	config[DEFAULT_IAM_ROLE_ARN] = defaultIAMRoleArn

	if answerFedType == AWS_FEDERATION_TYPE_OIDC {
		oidcSetup(ui, config)
	} else if answerFedType == AWS_FEDERATION_TYPE_SAML2 {
		saml2Setup(ui, config)
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

func oidcSetup(ui *input.UI, config map[string]string) {
	awsRoleSessionName, _ := ui.Ask("AWS federation roleSessionName:", &input.Options{
		Required: true,
		Loop:     true,
	})
	config[AWS_FEDERATION_ROLE_SESSION_NAME] = awsRoleSessionName
}

func saml2Setup(ui *input.UI, config map[string]string) {
	answer, _ := ui.Ask(`Select the subject token type to exchange for SAML2 assertion:
	1. Access Token (urn:ietf:params:oauth:token-type:access_token)
	2. ID Token (urn:ietf:params:oauth:token-type:id_token)
  `, &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != "1" && s != "2" {
				return errors.New("Input must be number")
			}
			return nil
		},
	})
	var subjectTokenType string
	if answer == "1" {
		subjectTokenType = TOKEN_TYPE_ACCESS_TOKEN
	} else if answer == "2" {
		subjectTokenType = TOKEN_TYPE_ID_TOKEN
	}
	config[OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE] = subjectTokenType

	audience, _ := ui.Ask("Audience for token exchange:", &input.Options{
		Required: true,
		Loop:     true,
	})
	config[OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE] = audience
}
