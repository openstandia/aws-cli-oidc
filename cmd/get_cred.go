package cmd

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

var getCredCmd = &cobra.Command{
	Use:   "get-cred <OIDC provider name>",
	Short: "Get AWS credentials and out to stdout",
	Long:  `Get AWS credentials and out to stdout through your OIDC provider authentication.`,
	Run:   getCred,
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

type loginFlagsStruct struct {
}

type AWSCredentials struct {
	AWSAccessKey     string
	AWSSecretKey     string
	AWSSessionToken  string
	AWSSecurityToken string
	PrincipalARN     string
	Expires          time.Time
}

func init() {
	rootCmd.AddCommand(getCredCmd)
}

type LoginParams struct {
	ResponseType string `url:"response_type,omitempty"`
	ClientId     string `url:"client_id,omitempty"`
	RedirectUri  string `url:"redirect_uri,omitempty"`
	Display      string `url:"display,omitempty"`
	Scope        string `url:"scope,omitempty"`
}

type param struct {
	name  string
	label string
	mask  bool
}

func getCred(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		Writeln("The OIDC provider name is required")
		Exit(nil)
	}
	providerName := args[0]

	client, err := CheckInstalled(providerName)
	if err != nil {
		Writeln("Failed to login OIDC provider")
		Exit(err)
	}

	tokenResponse, err := doLogin(client)
	if err != nil {
		Writeln("Failed to login the OIDC provider")
		Exit(err)
	}

	Writeln("Login successful!")
	Traceln("ID token: %s", tokenResponse.IDToken)

	awsFedType := client.config.GetString(AWS_FEDERATION_TYPE)
	maxSessionDurationSecondsString := client.config.GetString(MAX_SESSION_DURATION_SECONDS)
	maxSessionDurationSeconds, err := strconv.ParseInt(maxSessionDurationSecondsString, 10, 64)
	if err != nil {
		maxSessionDurationSeconds = 3600
	}

	var awsCreds *AWSCredentials
	if awsFedType == AWS_FEDERATION_TYPE_OIDC {
		awsCreds, err = GetCredentialsWithOIDC(client, tokenResponse.IDToken, maxSessionDurationSeconds)
		if err != nil {
			Writeln("Failed to get aws credentials with OIDC")
			Exit(err)
		}
	} else {
		Writeln("Invalid AWS federation type")
		Exit(err)
	}

	Writeln("")

	Export("AWS_ACCESS_KEY_ID", awsCreds.AWSAccessKey)
	Export("AWS_SECRET_ACCESS_KEY", awsCreds.AWSSecretKey)
	Export("AWS_SESSION_TOKEN", awsCreds.AWSSessionToken)
}

func doLogin(client *OIDCClient) (*TokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot start local http server to handle login redirect")
	}
	port := listener.Addr().(*net.TCPAddr).Port

	clientId := client.config.GetString(CLIENT_ID)
	redirect := fmt.Sprintf("http://127.0.0.1:%d", port)
	v, err := pkce.CreateCodeVerifierWithLength(pkce.MaxLength)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot generate OAuth2 PKCE code_challenge")
	}
	challenge := v.CodeChallengeS256()
	verifier := v.String()

	authReq := client.Authorization().
		QueryParam("response_type", "code").
		QueryParam("client_id", clientId).
		QueryParam("redirect_uri", redirect).
		QueryParam("code_challenge", challenge).
		QueryParam("code_challenge_method", "S256").
		QueryParam("scope", "openid")

	additionalQuery := client.config.GetString(OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY)
	if additionalQuery != "" {
		queries := strings.Split(additionalQuery, "&")
		for _, q := range queries {
			kv := strings.Split(q, "=")
			if len(kv) == 1 {
				authReq = authReq.QueryParam(kv[0], "")
			} else if len(kv) == 2 {
				authReq = authReq.QueryParam(kv[0], kv[1])
			} else {
				return nil, errors.Errorf("Invalid additional query: %s", q)
			}
		}
	}
	url := authReq.Url()

	code := launch(client, url.String(), listener)
	if code != "" {
		return codeToToken(client, verifier, code, redirect)
	} else {
		return nil, errors.New("Login failed, can't retrieve authorization code")
	}
}

func launch(client *OIDCClient, url string, listener net.Listener) string {
	c := make(chan string)

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		url := req.URL
		q := url.Query()
		code := q.Get("code")

		res.Header().Set("Content-Type", "text/html")

		// Redirect to user-defined successful/failure page
		successful := client.RedirectToSuccessfulPage()
		if successful != nil && code != "" {
			url := successful.Url()
			res.Header().Set("Location", (&url).String())
			res.WriteHeader(302)
		}
		failure := client.RedirectToFailurePage()
		if failure != nil && code == "" {
			url := failure.Url()
			res.Header().Set("Location", (&url).String())
			res.WriteHeader(302)
		}

		// Response result page
		message := "Login "
		if code != "" {
			message += "successful"
		} else {
			message += "failed"
		}
		res.Header().Set("Cache-Control", "no-store")
		res.Header().Set("Pragma", "no-cache")
		res.WriteHeader(200)
		res.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<body>
%s
</body>
</html>
`, message)))

		if f, ok := res.(http.Flusher); ok {
			f.Flush()
		}

		time.Sleep(100 * time.Millisecond)

		c <- code
	})

	srv := &http.Server{}
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	defer srv.Shutdown(ctx)

	go func() {
		if err := srv.Serve(listener); err != nil {
			// cannot panic, because this probably is an intentional close
		}
	}()

	var code string
	if err := browser.OpenURL(url); err == nil {
		code = <-c
	}

	return code
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func codeToToken(client *OIDCClient, verifier string, code string, redirect string) (*TokenResponse, error) {
	form := client.ClientForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)

	Traceln("code2token params:", form)

	res, err := client.Token().Request().Form(form).Post()

	if err != nil {
		return nil, errors.Wrap(err, "Failed to turn code into token")
	}

	if res.Status() != 200 {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return nil, errors.Errorf("Failed to turn code into token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return nil, errors.Errorf("Failed to turn code into token")
	}

	var tokenResponse TokenResponse
	res.ReadJson(&tokenResponse)
	return &tokenResponse, nil
}
