package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	cofide_wimse_server "github.com/cofide-labs/wimse-s2s/wimse/server"
)

// This is a demo setup of using SPIFFE + WIMSE draft-ietf-wimse-s2s-protocol-00 with RFC 9421 auth option
// To simulate the proper use of HTTP signatures it does not use mTLS but uses port 80 HTTP.
// all identities use the spiffe:// prefix instead of wimse:// to not break the `spiffeid` package

func main() {
	if err := runInsecure(); err != nil {
		log.Fatal(err)
	}
}

func runInsecure() error {
	server := cofide_wimse_server.NewServer(&http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "You are very WIMSEcal!\n")
		}),
	})

	fmt.Println("Starting insecure server on :80")
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}
