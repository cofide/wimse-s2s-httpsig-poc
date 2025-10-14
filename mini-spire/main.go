package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	minispire "github.com/cofide/minispire/pkg/spire-devserver"
	spiredevserver "github.com/cofide/minispire/pkg/spire-devserver"
	wimse_pb "github.com/cofide/minispire/pkg/wimse"
	pb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

const (
trustDomain = "example.com"
	spireSocket = "/tmp/spire.sock"
)

func main() {
	fmt.Println("Building in-memory CA")

	kt := spiredevserver.KeyTypeECDSAP256
	ca, err := minispire.NewInMemoryCA(kt)
	if err != nil {
		log.Fatalf("failed to create in-memory CA: %v", err)
	}

	lis, err := net.Listen("unix", spireSocket)
	if err != nil {
		log.Fatalf("failed to listen to SPIRE socket: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(spiredevserver.NewCredentials()))

	wl := spiredevserver.NewWorkloadHandler(spiredevserver.Config{
		Domain: trustDomain,
		CA:     ca,
	})
	pb.RegisterSpiffeWorkloadAPIServer(grpcServer, wl)
	wimse_pb.RegisterSpireJWTPOPExtensionServer(grpcServer, wl)

	go func() {
		fmt.Println("SPIRE server listening on", spireSocket)
		grpcServer.Serve(lis)
	}()

	// listen for signals to stop the server
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
	<-osSignals

	fmt.Println("Shutting down server")
	lis.Close()
}
