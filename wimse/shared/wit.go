package shared

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/cofide/minispire/pkg/wimse"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GetWITSVID(spireAddr string) (*pb.WITSVID, error) {
	// dial the SpiffeAddr with gRPC
	cc, err := grpc.DialContext(context.TODO(), spireAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("unable to dial socket: %w", err)
	}

	client := pb.NewMiniSPIREWorkloadAPIClient(cc)
	resp, err := client.MintWITSVID(context.TODO(), &pb.WITSVIDRequest{})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch WIT SVID: %w", err)
	}

	svids := resp.GetSvids()
	if len(svids) == 0 {
		return nil, fmt.Errorf("no SVIDs returned")
	}

	return svids[0], nil
}

func ParseWITSVIDKey(encoded string) (*ecdsa.PrivateKey, error) {
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

func AssertWIT(wit string) error {
	parts := strings.Split(wit, ".")
	if len(parts) != 3 {
		return fmt.Errorf("wit jws should comprise of 3 parts: header, payload, signature")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var claimsHeader map[string]interface{}
	if err := json.Unmarshal(header, &claimsHeader); err != nil {
		return err
	}
	if err := validateWITHeader(claimsHeader); err != nil {
		return err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var claimsPayload map[string]interface{}
	if err := json.Unmarshal(payload, &claimsPayload); err != nil {
		return err
	}
	if err := validateWITPayload(claimsPayload); err != nil {
		return err
	}

	printWIT(claimsHeader, claimsPayload)

	return nil
}

func printWIT(header, payload map[string]interface{}) {
	fmt.Println("WIT header and payload:")
	prettyPrint(header)
	prettyPrint(payload)
	fmt.Println("")
	fmt.Println("")
}

func prettyPrint(blob map[string]interface{}) {
	pretty, _ := json.MarshalIndent(blob, "", "  ")
	fmt.Printf(string(pretty))
}

func validateWITHeader(data map[string]interface{}) error {
	// Section 3.1 The Workload Identity Token
	// A WIT MUST contain the following claims, except where noted
	// in the JOSE header
	// alg, typ
	return mustContain(data, []string{"alg", "typ"})
}

func validateWITPayload(data map[string]interface{}) error {
	// Section 3.1 The Workload Identity Token
	// A WIT MUST contain the following claims, except where noted
	// in the JWT claims
	// iss, sub, exp, jti
	// cnf { jwk { alg } }
	err := mustContain(data, []string{"iss", "sub", "exp", "jti", "cnf"})
	if err != nil {
		return err
	}
	confirmation, ok := data["cnf"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid cnf")
	}

	err = mustContain(confirmation, []string{"jwk"})
	if err != nil {
		return err
	}
	jwk, ok := confirmation["jwk"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid cnf.jwk")
	}
	return mustContain(jwk, []string{"alg"})
}

func mustContain(data map[string]interface{}, keys []string) error {
	var missingOrEmpty []string
	for _, key := range keys {
		val, ok := data[key]
		if !ok || isEmpty(val) {
			missingOrEmpty = append(missingOrEmpty, key)
		}
	}
	if len(missingOrEmpty) > 0 {
		return fmt.Errorf("missing or empty required keys: %v", missingOrEmpty)
	}
	return nil
}

func isEmpty(val any) bool {
	if val == nil {
		return true
	}

	switch val.(type) {
	case string:
		return val == ""
	case map[string]interface{}:
		return len(val.(map[string]interface{})) == 0
	case int, int64, float64:
		return false
	}

	return true
}
