package main

import (
	"io"
	"os"
	"time"

	cofide_wimse "github.com/cofide/wimse-s2s-httpsig-poc/wimse/client"
)

// This is a demo setup of using SPIFFE + WIMSE draft-ietf-wimse-s2s-protocol with RFC 9421 auth option
// To simulate the proper use of HTTP signatures it does not use mTLS but uses port 80 HTTP.
// all identities use the spiffe:// prefix instead of wimse:// to not break the `spiffeid` package

func main() {
	url := "http://localhost:8080"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	// cofide_wimse is a http.Client interface that automatically adds WITs and signatures to requests
	c := cofide_wimse.NewClient()
	for {
		resp, err := c.Get(url)
		if err != nil {
			panic(err)
		}

		// print body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		println(string(body))
		resp.Body.Close()

		time.Sleep(time.Second * 10)
	}
}
