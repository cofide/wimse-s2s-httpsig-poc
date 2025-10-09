package cofide_wimse_server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/cofide/wimse-s2s-httpsig-poc/internal/spirehelper"
	"github.com/cofide/wimse-s2s-httpsig-poc/wimse/pb"
	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/yaronf/httpsign"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Server struct {
	// internal HTTP server
	http *http.Server

	// consumer given http server
	upstreamHTTP *http.Server

	*spirehelper.SpireHelper
}

func NewServer(server *http.Server, opts ...ServerOption) *Server {
	s := &Server{
		upstreamHTTP: server,
		SpireHelper: &spirehelper.SpireHelper{
			Ctx:        context.Background(),
			SpireAddr:  "unix:///tmp/spire.sock",
			Authorizer: tlsconfig.AuthorizeAny(),
		},
	}

	if os.Getenv("SPIFFE_ENDPOINT_SOCKET") != "" {
		s.SpireAddr = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Server) getHttp() *http.Server {
	var upstreamHandler http.Handler = http.DefaultServeMux
	if s.upstreamHTTP.Handler != nil {
		upstreamHandler = s.upstreamHTTP.Handler
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.EnsureSpire()
		s.WaitReady()

		jwt, err := jose.ParseSigned(r.Header.Get("workload-identity-token"), []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			log.Printf("Invalid token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var payload struct {
			Sub string `json:"sub"`
			Cnf struct {
				Jwk jose.JSONWebKey `json:"jwk"`
			} `json:"cnf"`
		}
		if err := json.Unmarshal(jwt.UnsafePayloadWithoutVerification(), &payload); err != nil {
			log.Printf("Invalid payload: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		sid, err := spiffeid.FromString(payload.Sub)
		if err != nil {
			log.Printf("Invalid SPIFFE ID: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// verify request
		jwtAuthority, err := s.GetJWTAuthority(sid)
		if err != nil {
			log.Printf("Unable to get JWT authority: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if _, err := jwt.Verify(jwtAuthority); err != nil {
			log.Printf("Untrustred token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		clientEcdsa, ok := payload.Cnf.Jwk.Key.(*ecdsa.PublicKey)
		if !ok {
			log.Printf("Invalid key type: %T\n", payload.Cnf.Jwk.Key)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		verifier, err := httpsign.NewP256Verifier(*clientEcdsa, httpsign.NewVerifyConfig().SetKeyID("wimse"), httpsign.Headers("@request-target", "Workload-Identity-Token"))
		if err != nil {
			log.Printf("Unable to create verifier: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		err = httpsign.VerifyRequest("wimse", *verifier, r)
		if err != nil {
			log.Printf("Invalid signature: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// sign the response

		svid, err := s.X509Source.GetX509SVID()
		if err != nil {
			log.Printf("Unable to get SVID: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ecdsa, ok := svid.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			log.Printf("Invalid key type: %T\n", svid.PrivateKey)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		jwk := jose.JSONWebKey{
			Key:       svid.PrivateKey.Public(),
			Algorithm: string(jose.ES256),
		}

		token, err := s.GetPOPAttested(jwk, fmt.Sprintf("%s://%s", r.Host, r.Proto))
		if err != nil {
			log.Printf("Unable to get POP attested token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		capture := httptest.NewRecorder()
		upstreamHandler.ServeHTTP(capture, r)

		resp := capture.Result()
		resp.Header.Set("workload-identity-token", token)

		resp.Header.Set("content-length", fmt.Sprintf("%d", capture.Body.Len()))
		if resp.Header.Get("Date") == "" {
			resp.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}

		signedHeaders := []string{"@status", "date", "workload-identity-token"}
		if resp.Body != nil {
			digest, err := httpsign.GenerateContentDigestHeader(&resp.Body, []string{httpsign.DigestSha256})
			if err != nil {
				log.Printf("Unable to generate content digest: %v\n", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			resp.Header.Set("content-digest", digest)
			signedHeaders = append(signedHeaders, "content-digest")
		}

		mustSignIfPresent := []string{"content-type", "content-length", "authorization", "txn-token"}
		for _, header := range mustSignIfPresent {
			if resp.Header.Get(header) != "" {
				signedHeaders = append(signedHeaders, header)
			}
		}

		signer, err := httpsign.NewP256Signer(*ecdsa, httpsign.NewSignConfig().SetKeyID("wimse"), httpsign.Headers(signedHeaders...))
		if err != nil {
			log.Printf("Unable to create signer: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sigInput, sig, err := httpsign.SignResponse("wimse", *signer, resp, r)
		if err != nil {
			log.Printf("Unable to sign response: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		for k, v := range resp.Header {
			w.Header().Set(k, v[0])
		}
		w.Header().Set("Signature", sig)
		w.Header().Set("Signature-Input", sigInput)

		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("Unable to copy body: %v\n", err)
		}
	})

	if s.http != nil {
		s.http.TLSConfig = s.upstreamHTTP.TLSConfig
		s.http.Handler = handler
		s.http.Addr = s.upstreamHTTP.Addr
		s.http.ReadTimeout = s.upstreamHTTP.ReadTimeout
		s.http.ReadHeaderTimeout = s.upstreamHTTP.ReadHeaderTimeout
		s.http.WriteTimeout = s.upstreamHTTP.WriteTimeout
		s.http.IdleTimeout = s.upstreamHTTP.IdleTimeout
		s.http.MaxHeaderBytes = s.upstreamHTTP.MaxHeaderBytes
		s.http.ConnState = s.upstreamHTTP.ConnState
		s.http.ErrorLog = s.upstreamHTTP.ErrorLog
		s.http.BaseContext = s.upstreamHTTP.BaseContext
		s.http.ConnContext = s.upstreamHTTP.ConnContext
		s.http.DisableGeneralOptionsHandler = s.upstreamHTTP.DisableGeneralOptionsHandler

		return s.http
	}

	s.http = &http.Server{
		TLSConfig:                    s.upstreamHTTP.TLSConfig,
		Handler:                      handler,
		Addr:                         s.upstreamHTTP.Addr,
		ReadTimeout:                  s.upstreamHTTP.ReadTimeout,
		ReadHeaderTimeout:            s.upstreamHTTP.ReadHeaderTimeout,
		WriteTimeout:                 s.upstreamHTTP.WriteTimeout,
		IdleTimeout:                  s.upstreamHTTP.IdleTimeout,
		MaxHeaderBytes:               s.upstreamHTTP.MaxHeaderBytes,
		ConnState:                    s.upstreamHTTP.ConnState,
		ErrorLog:                     s.upstreamHTTP.ErrorLog,
		BaseContext:                  s.upstreamHTTP.BaseContext,
		ConnContext:                  s.upstreamHTTP.ConnContext,
		DisableGeneralOptionsHandler: s.upstreamHTTP.DisableGeneralOptionsHandler,
	}

	return s.http
}

func (w *Server) Close() error {
	return w.getHttp().Close()
}
func (w *Server) ListenAndServe() error {
	w.EnsureSpire()
	w.WaitReady()

	return w.getHttp().ListenAndServe()
}
func (w *Server) ListenAndServeTLS(_, _ string) error {
	w.EnsureSpire()
	w.WaitReady()
	return w.getHttp().ListenAndServeTLS("", "") // certs and keys verridden by SPIRE
}
func (w *Server) RegisterOnShutdown(f func()) {
	w.EnsureSpire()
	w.WaitReady()
	w.getHttp().RegisterOnShutdown(f)
}
func (w *Server) Serve(l net.Listener) error {
	return w.ServeTLS(l, "", "") // certs and keys verridden by SPIRE
}
func (w *Server) ServeTLS(l net.Listener, _, _ string) error {
	w.EnsureSpire()
	w.WaitReady()
	return w.getHttp().ServeTLS(l, "", "") // certs and keys verridden by SPIRE
}
func (w *Server) SetKeepAlivesEnabled(v bool) {
	w.getHttp().SetKeepAlivesEnabled(v)
}
func (w *Server) Shutdown(ctx context.Context) error {
	return w.getHttp().Shutdown(ctx)
}

func (s *Server) GetJWTAuthority(id spiffeid.ID) (crypto.PublicKey, error) {
	trust, err := s.JWTSource.GetJWTBundleForTrustDomain(id.TrustDomain())
	if err != nil {
		return nil, fmt.Errorf("unable to get JWT bundle: %w", err)
	}
	keys := []string{}
	for k := range trust.JWTAuthorities() {
		keys = append(keys, k)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found")
	}

	return trust.JWTAuthorities()[keys[0]], nil
}

func (c *Server) GetPOPAttested(jwk jose.JSONWebKey, audience string) (string, error) {
	// dial the SpiffeAddr with gRPC
	cc, err := grpc.DialContext(context.TODO(), c.SpireAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", err
	}

	key, err := jwk.MarshalJSON()
	if err != nil {
		return "", err
	}

	client := pb.NewSpireJWTPOPExtensionClient(cc)
	resp, err := client.FetchJWTPOP(context.TODO(), &pb.JWTPOPRequest{
		Key:      string(key),
		Audience: audience,
	})
	if err != nil {
		return "", err
	}

	svids := resp.GetSvids()
	if len(svids) == 0 {
		return "", fmt.Errorf("no SVIDs returned")
	}

	return svids[0].Svid, nil
}
