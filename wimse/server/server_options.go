package cofide_wimse_server

import (
	"context"

	"github.com/cofide/wimse-s2s-httpsig-poc/id"
)

type ServerOption func(*Server)

func WithSpireAddress(addr string) ServerOption {
	return func(h *Server) {
		h.SpireAddr = addr
	}
}

func WithContext(ctx context.Context) ServerOption {
	return func(h *Server) {
		h.Ctx = ctx
	}
}

func WithSVIDMatch(funcs ...id.MatchFunc) ServerOption {
	return func(h *Server) {
		h.Authorizer = id.AuthorizeMatch(funcs...)
	}
}
