package lib

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	input "github.com/natsukagami/go-input"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
)

func GetCredentialsWithSAML(samlResponse string, durationSeconds int64, iamRoleArn string) (*AWSCredentials, error) {
	role, err := selectAwsRole(samlResponse, iamRoleArn)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to assume role, please check you are permitted to assume the given role for the AWS service")
	}

	Writeln("Selected role: %s", role.RoleARN)
	Writeln("Max Session Duration: %d seconds", durationSeconds)

	return loginToStsUsingRole(role, samlResponse, durationSeconds)
}

func selectAwsRole(samlResponse, iamRoleArn string) (*saml2aws.AWSRole, error) {
	roles, err := saml2aws.ExtractAwsRoles([]byte(samlResponse))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to extract aws roles from SAML Assertion")
	}

	if len(roles) == 0 {
		return nil, errors.New("No roles to assume, check you are permitted to assume roles for the AWS service")
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse aws roles")
	}

	return resolveRole(awsRoles, samlResponse, iamRoleArn)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion, iamRoleArn string) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("No roles available")
	}

	Writeln("")

	for {
		var err error
		role, err = promptForAWSRoleSelection(awsRoles, iamRoleArn)
		if err == nil {
			break
		}
		Writeln("Selecting role, try again. Error: %v", err)
	}

	return role, nil
}

func promptForAWSRoleSelection(awsRoles []*saml2aws.AWSRole, iamRoleArn string) (*saml2aws.AWSRole, error) {
	roles := map[string]*saml2aws.AWSRole{}
	var roleOptions []string

	for _, role := range awsRoles {
		if iamRoleArn == role.RoleARN {
			Writeln("Selected default role: %s", iamRoleArn)
			return role, nil
		}
		roles[role.RoleARN] = role
		roleOptions = append(roleOptions, role.RoleARN)
	}

	if iamRoleArn != "" {
		Writeln("Warning: You don't have the default role: %s", iamRoleArn)
	}

	sort.Strings(roleOptions)
	var showList string
	for i, role := range roleOptions {
		showList = showList + fmt.Sprintf("  %d. %s\n", i+1, role)
	}

	ui := &input.UI{
		Writer: os.Stderr,
		Reader: os.Stdin,
	}

	answer, _ := ui.Ask(fmt.Sprintf("Please choose the role [1-%d]:\n\n%s", len(awsRoles), showList), &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			i, err := strconv.Atoi(s)
			if err != nil || i < 1 || i > len(awsRoles) {
				return errors.New(fmt.Sprintf("Please choose the role [1-%d]", len(awsRoles)))
			}
			return nil
		},
	})
	i, _ := strconv.Atoi(answer)

	return roles[roleOptions[i-1]], nil
}

func loginToStsUsingRole(role *saml2aws.AWSRole, samlResponse string, durationSeconds int64) (*AWSCredentials, error) {
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
		DurationSeconds: aws.Int64(durationSeconds),
	}

	Writeln("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve STS credentials using SAML")
	}

	Traceln("Got AWS credentials using SAML assertion")

	return &AWSCredentials{
		AWSAccessKey:    aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:    aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:    aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}
