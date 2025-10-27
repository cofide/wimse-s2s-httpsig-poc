package shared

import (
	"context"
	"fmt"

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
		return nil, fmt.Errorf("unable to fetch JWT POP: %w", err)
	}

	svids := resp.GetSvids()
	if len(svids) == 0 {
		return nil, fmt.Errorf("no SVIDs returned")
	}

	return svids[0], nil
}
