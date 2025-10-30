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
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var claimsHeader map[string]interface{}
	if err := json.Unmarshal(header, &claimsHeader); err != nil {
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

	if err := mustContain(claimsHeader, []string{"alg", "typ"}); err != nil {
		return err
	}

	if err := mustContain(claimsPayload, []string{"iss", "sub", "exp", "jti", "cnf"}); err != nil {
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

func mustContain(data map[string]interface{}, keys []string) error {
	var missing []string

	for _, key := range keys {
		_, ok := data[key]
		if !ok {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing or empty required keys: %v", missing)
	}
	return nil
}
