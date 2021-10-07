package lib

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Wrapper around net/url and net/http.  Fluent style modeled from Java's JAX-RS

type OAuthError struct {
	err         string `json:"error"`
	description string `json:"error_description"`
}

type RestClient struct {
	httpClient *http.Client
}

type RestClientConfig struct {
	ClientCert         string
	ClientKey          string
	ClientCA           string
	InsecureSkipVerify bool
}

type WebTarget struct {
	url    url.URL
	client *RestClient
}

type Request struct {
	headers http.Header
	body    io.Reader
	url     *url.URL
	client  *RestClient
}

type Response struct {
	res *http.Response
}

func NewRestClient(config *RestClientConfig) (*RestClient, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Setup for client auth
	if config.ClientCert != "" && config.ClientKey != "" {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, err
		}

		// Load CA cert
		caCert, err := ioutil.ReadFile(config.ClientCA)
		if err != nil {
			return nil, err
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			caCertPool = x509.NewCertPool()
		}
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &RestClient{
		httpClient: httpClient,
	}, nil
}

func (client *RestClient) Target(uri string) *WebTarget {

	url, err := url.Parse(uri)
	if err != nil {
		return nil
	}
	return &WebTarget{
		url:    *url,
		client: client,
	}
}

func (target *WebTarget) Url() url.URL {
	return target.url
}

func (target *WebTarget) Path(path string) *WebTarget {
	newTarget := &WebTarget{
		url:    target.url,
		client: target.client,
	}

	if strings.HasSuffix(target.url.Path, "/") {
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
	} else {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path

		}
	}
	newTarget.url.Path = target.url.Path + path
	return newTarget
}

func (target *WebTarget) QueryParam(name string, value string) *WebTarget {
	newTarget := &WebTarget{
		url:    target.url,
		client: target.client,
	}
	q := newTarget.url.Query()
	q.Set(name, value)
	newTarget.url.RawQuery = q.Encode()
	return newTarget
}

func (target *WebTarget) Request() *Request {
	return &Request{
		url:     &target.url,
		client:  target.client,
		headers: make(http.Header),
	}
}

func (r *Request) Form(form url.Values) *Request {
	r.headers.Set("Content-Type", "application/x-www-form-urlencoded")
	r.body = strings.NewReader(form.Encode())
	return r
}

func (r *Request) Json(v interface{}) *Request {
	r.headers.Set("Content-Type", "application/json")
	body, _ := json.Marshal(v)
	r.body = bytes.NewBuffer(body)
	return r
}

func (r *Request) Header(name string, value string) *Request {
	r.headers.Set(name, value)
	return r
}

func (r *Request) Get() (*Response, error) {
	request, _ := http.NewRequest("GET", r.url.String(), nil)
	request.Header = r.headers
	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return &Response{res: res}, nil
}

func (r *Request) Delete() (*Response, error) {
	request, _ := http.NewRequest("DELETE", r.url.String(), nil)
	request.Header = r.headers
	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return &Response{res: res}, nil
}

func (r *Request) Post() (*Response, error) {
	request, _ := http.NewRequest("POST", r.url.String(), r.body)
	request.Header = r.headers
	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return &Response{res: res}, nil
}

func (r *Request) Put() (*Response, error) {
	request, err := http.NewRequest("Put", r.url.String(), r.body)
	if err != nil {
		return nil, err
	}
	request.Header = r.headers
	res, err := r.client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return &Response{res: res}, nil
}

func (r *Response) Status() int {
	return r.res.StatusCode
}

func (r *Response) Location() string {
	return r.res.Header.Get("Location")
}

func (r *Response) ReadJson(data interface{}) error {
	body, readErr := ioutil.ReadAll(r.res.Body)
	if readErr != nil {
		return readErr
	}
	return json.Unmarshal(body, data)
}

func (r *Response) ReadText() (string, error) {
	body, err := ioutil.ReadAll(r.res.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (r *Response) ReadBytes() ([]byte, error) {
	body, err := ioutil.ReadAll(r.res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (r *Response) MediaType() string {
	return r.res.Header.Get("Content-Type")
}

func (r *Response) Header(name string) string {
	return r.res.Header.Get(name)
}
