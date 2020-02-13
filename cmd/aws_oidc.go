package cmd

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
)

func GetCredentialsWithOIDC(client *OIDCClient, idToken string, durationSeconds int64) (*AWSCredentials, error) {
	return loginToStsUsingIDToken(client, idToken, durationSeconds)
}

func loginToStsUsingIDToken(client *OIDCClient, idToken string, durationSeconds int64) (*AWSCredentials, error) {
	role := client.config.GetString(AWS_FEDERATION_ROLE)
	roleSessionName := client.config.GetString(AWS_FEDERATION_ROLE_SESSION_NAME)

	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &role,
		RoleSessionName:  &roleSessionName,
		WebIdentityToken: &idToken,
		DurationSeconds:  aws.Int64(durationSeconds),
	}

	Writeln("Requesting AWS credentials using ID Token")

	resp, err := svc.AssumeRoleWithWebIdentity(params)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using ID Token")
	}

	return &AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
	}, nil
}
