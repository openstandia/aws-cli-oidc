package cmd

import (
	"encoding/base64"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
)

func GetCredentialsWithSAML(samlResponse string) (*AWSCredentials, error) {
	role, err := selectAwsRole(samlResponse)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to assume role, please check you are permitted to assume the given role for the AWS service")
	}

	Writeln("Selected role: %s", role.RoleARN)

	return loginToStsUsingRole(role, samlResponse)
}

func selectAwsRole(samlResponse string) (*saml2aws.AWSRole, error) {
	roles, err := saml2aws.ExtractAwsRoles([]byte(samlResponse))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to extract aws roles")
	}

	if len(roles) == 0 {
		return nil, errors.New("No roles to assume, check you are permitted to assume roles for the AWS service")
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse aws roles")
	}

	return resolveRole(awsRoles, samlResponse)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion string) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("No roles available")
	}

	awsAccounts, err := saml2aws.ParseAWSAccounts(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse aws role accounts")
	}

	saml2aws.AssignPrincipals(awsRoles, awsAccounts)

	for {
		role, err = saml2aws.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		Writeln("Selecting role, try again")
	}

	return role, nil
}

func loginToStsUsingRole(role *saml2aws.AWSRole, samlResponse string) (*AWSCredentials, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session")
	}

	Traceln("SAMLReponse: %s", samlResponse)

	b := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	svc := sts.New(sess)

	Traceln("PrincipalARN: %s", role.PrincipalARN)
	Traceln("RoleARN: %s", role.RoleARN)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(b),                 // Required
		DurationSeconds: aws.Int64(int64(900)),
	}

	Writeln("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve STS credentials using SAML")
	}

	Traceln("Got AWS credentials using SAML assertion")

	return &AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
	}, nil
}
