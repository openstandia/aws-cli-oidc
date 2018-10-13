# aws-cli-oidc

CLI tool for retrieving AWS temporary credentials using OIDC provider.


## Install

Download from [Releases page](https://github.com/openstandia/aws-cli-oidc/releases).


## Prerequisite AWS and OIDC provider settings before using this tool

Before using this tool, you or the system administrator need to setup the following configuration.

- Identity Federation using SAML2/OIDC between AWS and the OIDC provider. See https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html
- Registration OIDC/OAuth2 client for this CLI tool in the OIDC provider. Note: The OIDC provider must allow any port to be specified at the time of the request for loopback IP redirect URIs because this tool follows [RFC 8252 OAuth 2.0 for Native Apps 7.3 Loopback Interface Redirection](https://tools.ietf.org/html/rfc8252#section-7.3).

Also depending on the federation method between AWS and the OIDC provider, requirements for the OIDC providers will change.

## For SAML2
- Of course, the OIDC provider must support not only OIDC but also SAML2 for federation between itself and AWS.
- The OIDC provider must support [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-15) for exchanging OAuth/OIDC token and SAML2 assertion. `aws-cli-oidc` gets access token/ID token from the OIDC provider first, then it needs to get SAML2 assertion from the provider which is required for getting AWS temporary credentials using AWS STS API.

## For OIDC
- The OIDC provider only needs to support OIDC. SAML2 and OAuth 2.0 Token Exchange are not necessary. Very simple.
- However, the JWKS endpoint of the OIDC provider needs to export it to the Internet because AWS try to access the endpoint to obtain the public key and to verify the ID token which is issued by the provider.


## Tested OIDC Provider

Currently I tested this tool using [Keycloak](https://keycloak.org) as the OIDC provider.
Note: You can't use SAML2 without extension which supports exchanging from access token to SAML2 assertion because Keycloak supports [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-15) partially and doesn't support SAML2 assertion yet.


## Usage

```
CLI tool for retrieving AWS temporary credentials using OIDC provider

Usage:
  aws-cli-oidc [command]

Available Commands:
  get-cred    Get AWS credentials and out to stdout
  help        Help about any command
  setup       Interactive setup of aws-cli-oidc

Flags:
  -h, --help   help for aws-cli-oidc

Use "aws-cli-oidc [command] --help" for more information about a command.
```


### Setup

Use `aws-cli-oidc setup` command and follow the guide.


### Get AWS temporary credentials

Use `aws-cli-oidc get-cred <your oidc provider name>` command. It opens your browser.
Now you can see the login page which the OIDC provider offers. Then do login.
If successful, AWS temporary credentials will be shown as below.

```
aws-cli-oidc get-cred myop
Using config file: /home/wadahiro/.aws-cli-oidc/config.yaml
Login successful!
Selected role: arn:aws:iam::123456789012:role/developer
PrincipalARN: arn:aws:iam::123456789012:saml-provider/myop
RoleARN: arn:aws:iam::123456789012:role/developer

export AWS_ACCESS_KEY_ID=ASIAT......
export AWS_SECRET_ACCESS_KEY=9bkS0whPelMYQ.......
export AWS_SESSION_TOKEN=FQoGZXIvYXdzENz.......
```


## Licence

Licensed under the [MIT](/LICENSE) license.


## Author

- [Hiroyuki Wada](https://github.com/wadahiro)
