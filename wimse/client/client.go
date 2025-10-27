package cofide_wimse

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/cofide/minispire/pkg/wimse"
	"github.com/cofide/wimse-s2s-httpsig-poc/internal/spirehelper"
	"github.com/cofide/wimse-s2s-httpsig-poc/wimse/shared"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/yaronf/httpsign"
)

var nonceCounter atomic.Uint64

type Client struct {
	*spirehelper.SpireHelper

	/** FROM THIS POINT ALL PROPERTIES COME FROM net/http **/

	// Transport specifies the mechanism by which individual
	// HTTP requests are made.
	// If nil, DefaultTransport is used.
	Transport http.RoundTripper

	// CheckRedirect specifies the policy for handling redirects.
	// If CheckRedirect is not nil, the client calls it before
	// following an HTTP redirect. The arguments req and via are
	// the upcoming request and the requests made already, oldest
	// first. If CheckRedirect returns an error, the Client's Get
	// method returns both the previous Response (with its Body
	// closed) and CheckRedirect's error (wrapped in a url.Error)
	// instead of issuing the Request req.
	// As a special case, if CheckRedirect returns ErrUseLastResponse,
	// then the most recent response is returned with its body
	// unclosed, along with a nil error.
	//
	// If CheckRedirect is nil, the Client uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect func(req *http.Request, via []*http.Request) error

	// Jar specifies the cookie jar.
	//
	// The Jar is used to insert relevant cookies into every
	// outbound Request and is updated with the cookie values
	// of every inbound Response. The Jar is consulted for every
	// redirect that the Client follows.
	//
	// If Jar is nil, cookies are only sent if they are explicitly
	// set on the Request.
	Jar http.CookieJar

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, any
	// redirects, and reading the response body. The timer remains
	// running after Get, Head, Post, or Do return and will
	// interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	//
	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	//
	// For compatibility, the Client will also use the deprecated
	// CancelRequest method on Transport if found. New
	// RoundTripper implementations should use the Request's Context
	// for cancellation instead of implementing CancelRequest.
	Timeout time.Duration
}

func NewClient(opts ...ClientOption) *Client {
	c := &Client{

		SpireHelper: &spirehelper.SpireHelper{
			Ctx:        context.Background(),
			SpireAddr:  "unix:///tmp/spire.sock",
			Authorizer: tlsconfig.AuthorizeAny(),
		},
	}

	if os.Getenv("SPIFFE_ENDPOINT_SOCKET") != "" {
		c.SpireAddr = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) GetWITSVID() (*pb.WITSVID, error) {
	return shared.GetWITSVID(c.SpireAddr)
}

func (c *Client) getHttp(req *http.Request) (*httpsign.Client, error) {
	signedHeaders := []string{"@method", "@request-target", "Workload-Identity-Token"}
	if req.Body != nil {
		signedHeaders = append(signedHeaders, "content-digest")
	}

	mustSignIfPresent := []string{"content-type", "authorization", "Txn-Token"}
	for _, header := range mustSignIfPresent {
		if req.Header.Get(header) != "" {
			signedHeaders = append(signedHeaders, header)
		}
	}

	svid, err := c.GetWITSVID()
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.ParseSigned(svid.WitSvid, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	claims := jwt.Claims{}
	if err := parsedToken.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}

	x, err := parseWITSVIDKey(svid.WitSvidKey)
	if err != nil {
		return nil, err
	}
	signer, _ := httpsign.NewP256Signer(*x, httpsign.NewSignConfig().
		SetNonce(getNonce(req)).
		SetTag("wimse-service-to-service").
		SetExpires(claims.Expiry.Time().Unix()),
		httpsign.Headers(signedHeaders...))

	req.Header.Set("workload-identity-token", svid.WitSvid)

	return httpsign.NewDefaultClient(httpsign.NewClientConfig().SetSignatureName("wimse").SetSigner(signer)), nil
}

func parseWITSVIDKey(encoded string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode key: %v", err)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	return parsedKey.(*ecdsa.PrivateKey), nil
}

func (c *Client) CloseIdleConnections() {
	// Unimplemented due to lack of support in the underlying httpsign.Client
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	c.EnsureSpire()
	c.WaitReady()

	client, err := c.getHttp(req)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// log all request and response headers

	fmt.Println("Request:")
	fmt.Printf("%s %s %s\n", req.Method, req.URL.Path, req.Proto)
	for k, v := range req.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}

	fmt.Println("")
	fmt.Println("Response:")
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}

	// verify the response

	jwt, err := jose.ParseSigned(resp.Header.Get("workload-identity-token"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("unable to parse token: %w", err)
	}

	var payload struct {
		Sub string `json:"sub"`
		Cnf struct {
			Jwk jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(jwt.UnsafePayloadWithoutVerification(), &payload); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	_, err = spiffeid.FromString(payload.Sub)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	keyBytes := payload.Cnf.Jwk.Key.([]byte)
	pubInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		log.Printf("failed to parse public key: %v", err)
		return nil, fmt.Errorf("unable to parse key: %w", err)
	}
	clientEcdsa := pubInterface.(*ecdsa.PublicKey)

	verifier, err := httpsign.NewP256Verifier(*clientEcdsa, httpsign.NewVerifyConfig().SetKeyID("wimse"), httpsign.Headers())
	if err != nil {
		return nil, fmt.Errorf("unable to create verifier: %w", err)
	}

	err = httpsign.VerifyResponse("wimse", *verifier, resp, req)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return resp, nil
}

func (c *Client) Get(url string) (resp *http.Response, err error) {
	c.EnsureSpire()
	c.WaitReady()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

func (c *Client) Head(url string) (resp *http.Response, err error) {
	c.EnsureSpire()
	c.WaitReady()

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	c.EnsureSpire()
	c.WaitReady()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	c.EnsureSpire()
	c.WaitReady()

	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	return c.Do(req)
}

func getNonce(req *http.Request) string {
	// generate a nonce that consits of the current time, a counter and the request's URL in sha256

	// get the current time
	now := time.Now().Unix()

	// get the request's URL
	url := req.URL.String()

	// get the counter
	counter := nonceCounter.Add(1)

	data := fmt.Sprintf("%d-%d-%s", now, counter, url)

	// sha256sum the data
	h := sha256.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Client) GetJWTAuthority(id spiffeid.ID) (crypto.PublicKey, error) {
	trust, err := s.JWTSource.GetJWTBundleForTrustDomain(id.TrustDomain())
	if err != nil {
		return "", fmt.Errorf("unable to get JWT bundle: %w", err)
	}
	keys := []string{}
	for k := range trust.JWTAuthorities() {
		keys = append(keys, k)
	}

	if len(keys) == 0 {
		return "", fmt.Errorf("no keys found")
	}

	return trust.JWTAuthorities()[keys[0]], nil
}
