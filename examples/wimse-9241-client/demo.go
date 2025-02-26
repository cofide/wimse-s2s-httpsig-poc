package main

import (
	"io"
	"time"

	cofide_wimse "github.com/cofide-labs/wimse-s2s/wimse/client"
)

// This is a demo setup of using SPIFFE + WIMSE draft-ietf-wimse-s2s-protocol-00 with RFC 9421 auth option
// To simulate the proper use of HTTP signatures it does not use mTLS but uses port 80 HTTP.
// all identities use the spiffe:// prefix instead of wimse:// to not break the `spiffeid` package

func main() {

	// Cofide SDK allows to secure your application in just ONE line of code

	c := cofide_wimse.NewClient()
	//c := http.Client{}

	for {
		resp, err := c.Get("http://localhost")
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
