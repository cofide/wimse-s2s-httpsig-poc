package id

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SPIFFEID is an **opinionated** implementation of the upstream spiffeid.ID
// it builds on top of the SPIFFE ID however carries a strong key-value based
// approach to encode the ID with its information.
// URLs are here used as a string representation of trust data as this can be
// used inside X.509 data easily as URI SAN.
//
// the data is encoded  as following:
// spiffe://<trust domain>/<key 1>/<value 1>/<key 2>/<value 2>
//
// There are a following set of default keys that MUST be encoded is attested:
//
// Local workloads:
// - uid (user id of caller)
// - gid (user group id of caller)
// - pid (process id)
// - bin (binary name, if available)
//
// Kubernetes workloads:
// - ns (namespace)
// - sa (service account)
// - deploy (deployment name)
type SPIFFEID struct {
	// SPIFFE ID
	id spiffeid.ID
}

func CreateID(trustDomain string, kv map[string]string) (*SPIFFEID, error) {
	// sort the keys to have a deterministic order
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pathKV := make([]string, 0, len(kv)*2)
	for _, k := range keys {
		pathKV = append(pathKV, k, kv[k])
	}
	id, err := spiffeid.FromString(fmt.Sprintf("spiffe://%s/%s", trustDomain, strings.Join(pathKV, "/")))
	if err != nil {
		return nil, fmt.Errorf("failed to create spiffe id: %w", err)
	}
	return &SPIFFEID{id: id}, nil
}

func MustCreateID(trustDomain string, kv map[string]string) *SPIFFEID {
	id, err := CreateID(trustDomain, kv)
	if err != nil {
		panic(err)
	}
	return id
}

func ParseID(id string) (*SPIFFEID, error) {
	upstreamID, err := spiffeid.FromString(id)
	if err != nil {
		return nil, fmt.Errorf("failed to parse spiffe id: %w", err)
	}
	svid := &SPIFFEID{id: upstreamID}

	if _, err := svid.ParsePath(); err != nil {
		return nil, fmt.Errorf("failed to parse path: %w", err)
	}

	return svid, nil
}

func MustParseID(id string) *SPIFFEID {
	svid, err := ParseID(id)
	if err != nil {
		panic(err)
	}
	return svid
}

func (s *SPIFFEID) ParsePath() (map[string]string, error) {
	path := s.id.Path()
	path = strings.Trim(path, "/")
	pathParts := strings.Split(path, "/")

	if len(pathParts)%2 != 0 {
		return nil, fmt.Errorf("invalid path, needs to be even in parts: %s", path)
	}

	kv := make(map[string]string)
	for i := 0; i < len(pathParts); i += 2 {
		kv[pathParts[i]] = pathParts[i+1]
	}

	return kv, nil
}

func (s *SPIFFEID) TrustDomain() string {
	return s.id.TrustDomain().String()
}

func (s *SPIFFEID) String() string {
	return s.id.String()
}

func (s *SPIFFEID) ToSpiffeID() spiffeid.ID {
	return s.id
}
