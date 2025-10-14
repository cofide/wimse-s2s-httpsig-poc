package spirehelper

import (
	"context"
	"time"

	"github.com/cofide/wimse-s2s-httpsig-poc/internal/backoff"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type SpireHelper struct {
	X509Source *workloadapi.X509Source
	JWTSource  *workloadapi.JWTSource
	SpireAddr  string
	Ctx        context.Context

	Authorizer tlsconfig.Authorizer

	readyCh chan struct{}
	backoff *backoff.Backoff
}

func (s *SpireHelper) EnsureSpire() {
	if s.X509Source != nil {
		return
	}
	if s.backoff == nil {
		s.backoff = backoff.NewBackoff()
	}
	if s.readyCh == nil {
		s.readyCh = make(chan struct{})
	}

	go func() {
		for {
			var err error

			s.X509Source, err = workloadapi.NewX509Source(s.Ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(s.SpireAddr)))
			if err != nil {
				time.Sleep(s.backoff.Duration())
				continue
			}

			// attempt to get an X.509 SVID
			_, err = s.X509Source.GetX509SVID()
			if err != nil {
				time.Sleep(s.backoff.Duration())
				continue
			}

			// attempt to get a JWT SVID
			s.JWTSource, err = workloadapi.NewJWTSource(s.Ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(s.SpireAddr)))
			if err != nil {
				time.Sleep(s.backoff.Duration())
				continue
			}

			s.backoff.Reset()
			break
		}

		close(s.readyCh)
	}()
}

func (s *SpireHelper) WaitReady() {
	// wait till readyCh is closed
	<-s.readyCh
}
