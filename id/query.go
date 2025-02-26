package id

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/gobwas/glob"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

type MatchFunc func(kv map[string]string) error

func (s *SPIFFEID) Matches(funcs ...MatchFunc) (bool, error) {
	kv, err := s.ParsePath()
	if err != nil {
		return false, err
	}

	for _, f := range funcs {
		err := f(kv)
		if err != nil {
			return false, err
		}
	}

	return true, err
}

func AuthorizeMatch(funcs ...MatchFunc) tlsconfig.Authorizer {
	return func(id spiffeid.ID, verifiedChains [][]*x509.Certificate) error {
		svid, err := ParseID(id.String())
		if err != nil {
			return err
		}

		ok, err := svid.Matches(funcs...)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("did not match")
		}

		return nil
	}
}

func Equals(key, value string) MatchFunc {
	return func(kv map[string]string) error {
		if val, ok := kv[key]; !ok || val != value {
			return fmt.Errorf("key %s does not match value %s", key, value)
		}

		return nil
	}
}

func IsEmpty(key string) MatchFunc {
	return func(kv map[string]string) error {
		if kv[key] != "" {
			return fmt.Errorf("key %s is not empty", key)
		}

		return nil
	}
}

func IsNotEmpty(key string) MatchFunc {
	return func(kv map[string]string) error {
		if kv[key] == "" {
			return fmt.Errorf("key %s is empty", key)
		}

		return nil
	}
}

func MatchGlob(key, globStr string) MatchFunc {
	return func(kv map[string]string) error {
		g, err := glob.Compile(globStr)
		if err != nil {
			return fmt.Errorf("failed to compile glob %q: %w", globStr, err)
		}
		if val, ok := kv[key]; ok && !g.Match(val) {
			return fmt.Errorf("key %q with value %q does not match glob %q", key, val, globStr)
		}

		return nil
	}
}

func Or(funcs ...MatchFunc) MatchFunc {
	return func(kv map[string]string) error {
		errs := make([]error, 0, len(funcs))
		for _, f := range funcs {
			err := f(kv)
			errs = append(errs, err)
		}

		hasPassedTest := false
		for _, err := range errs {
			if err == nil {
				hasPassedTest = true
				break
			}
		}

		if !hasPassedTest {
			return fmt.Errorf("none of the tests passed")
		}

		return nil
	}
}

func Not(f MatchFunc) MatchFunc {
	return func(kv map[string]string) error {
		err := f(kv)
		if err == nil {
			return errors.New("Did not receive an error in NOT call")
		}

		return nil
	}
}
