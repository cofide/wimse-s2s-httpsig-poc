# WIMSE S2S with HTTP Signatures demo

This is a demo implementation of [WIMSE Service to Service Authentication](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) protocol "Option 2: Authentication Based on HTTP Message Signatures".

This demo utilises a demonstrator implementation `mini-spire` that can issue the correct key material to client and server. This is a simple way to get SPIFFE identities issued without the need of a whole SPIRE setup. As the setup of an SVID and WIT resemble each other a lot at time of writing this demo we built on top of this system with adding one gRPC call needed. We also switched the default to ECDSA certificates

We chose to develop this demo of WIMSE with HTTP signatures as a demo of solving the use case where you want authenticated and signed messaging with a middlebox.

A use case we often saw where using the more "traditional" mTLS approach was not possible.

## How it works

```
                             ┌─────────────────┐
                             │                 │
  +--------------------------│  Mini-Spire     │<-----------------------+
  |                          │  Server         │                        |
  |              +---------->│                 │-----------+            |
  |              |           └─────────────────┘           |            |
  │              |                                         │            |
  │ Issues SVID  │ Sign JWT                                │ Issues SVID|
  │ + JWT CA     │ POP                                     │  + JWT CA  | Sign JWT
  │              │                                         │            | POP
  ▼              │                                         ▼            |
┌─────────────────┐          ┌──────────────────┐     ┌─────────────────┐
│                 │          │                  │     │                 │
│  WIMSE enabled  │─────────▶│    Middlebox     │────▶│  WIMSE enabled  │
│  Client         │   HTTP   │  (e.g., CDN/     │     │  Server         │
│                 │  Request │   Cloudflare)    │     │                 │
└─────────────────┘   with   │                  |     └─────────────────┘
                      HTTP   │  Can inspect     │     
                      Sign   │  but not modify  │     
                      + WIT  │  the signed data │     
                             └──────────────────┘     
``` 



## Running the demo

To run the demo you need to run the mini-spire server:
```
go run ./mini-spire/cmd/mini-spire serve
```

Then in another terminal run the server:
```
go run ./examples/wimse-9421-server
```

At last run the client:
```
go run ./examples/wimse-9421-client
```

You will see the full request and response:
```
Request:
GET  HTTP/1.1
Workload-Identity-Token: eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IndpbXNlLWlkK2p3dCJ9.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJhbGciOiJFUzI1NiIsIngiOiJKVkpLdmREVVk1Wi1NTEN5dEkxcmpSb2tIN0xUTVZod0YwWkM0VVZTajgwIiwieSI6Iko3ZFJTeDZtdl9mVGlrdVZKNTlmYnp6dWVnOXVlMWxOa3RWbTJUVGVEd3MifX0sImV4cCI6MTc2MDAxNjY2MiwiaWF0IjoxNzYwMDE2MzYyLCJpc3MiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbSIsImp0aSI6IjYwNDE1ZmRhMzhiODFjNWU0ZWQzN2EzZjA5NTg3OTM5ZmIwZjQwOGRjZmU0MzE2OTRlODZjMDM5MjdiMzYyYTAiLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS9iaW4vd2ltc2UtOTQyMS1jbGllbnQvZ2lkLzEwMDAvcGlkLzQzMTM5OC91aWQvMTAwMCJ9.lkqugbSkVqZX4zMBo9yFWKIbHglaxmJkGCK2PoT0N-MG1Zv_RKqIGYaG9snZMWo_NZtcFxTfJQUswxvWUACruw
Signature: wimse=:lz2nQGpOAYeIc/JrCkd4ab7QEIGt7Fos3B3J3VBaUGLMyjNDakgW9unFdIJrd0SYOpVHPycsEyEQcs5HNy3hRg==:
Signature-Input: wimse=("@request-target" "workload-identity-token");created=1760016362;expires=1760016662;nonce="c920d7f920df71f8e377b9ecb843f4e9f800d38104c1b76ce905b969c3a3a076";alg="ecdsa-p256-sha256";tag="wimse-service-to-service"

Response:
HTTP/1.1 200 OK
Content-Digest: sha-256=:7JVJmgim6dP1haght1LWmS2hCitii6JgPiDrVLqTclw=:
Content-Length: 23
Content-Type: text/plain; charset=utf-8
Date: Thu, 09 Oct 2025 13:26:02 GMT
Signature: wimse=:mFlZf251pBkiGeqxonsaCcTVFME2sgwospdMu6KA0Y9eokOZ5rZkj871xYUus1WPcaNuR/LmD27y2yUXqTW7OQ==:
Signature-Input: wimse=("@status" "date" "workload-identity-token" "content-digest" "content-type" "content-length");created=1760016362;alg="ecdsa-p256-sha256";keyid="wimse"
Workload-Identity-Token: eyJhbGciOiJFUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IndpbXNlLWlkK2p3dCJ9.eyJhdWQiOiJsb2NhbGhvc3Q6ODA4MDovL0hUVFAvMS4xIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYiLCJ4IjoiX0ZkWklZdkpYWmVwckNGX1VsM3U2UXhGeWhvWFNPUXJaRG5mcFVPbUpidyIsInkiOiJzZkRJZ1NwaTdXTlZjVXpYSkkzaWhhQ3JCOUkyVDYtWXVyTzNRVHZzZWd3In19LCJleHAiOjE3NjAwMTY2NjIsImlhdCI6MTc2MDAxNjM2MiwiaXNzIjoic3BpZmZlOi8vZXhhbXBsZS5jb20iLCJqdGkiOiJmYjU2ZDQ4ZjYyYTZkODA4YTFiZmUzNmNiYjBhNmMyZjBmMWE4MDBiN2ExN2I0Yzg4MjZmNGY0MTZmMTBlNTNmIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5jb20vYmluL3dpbXNlLTk0MjEtc2VydmVyL2dpZC8xMDAwL3BpZC80MTA3MDAvdWlkLzEwMDAifQ.glwwGnbfNV62IYr2R3ha_UEVp97wEj92J8KyE20ZJbnwhfOhd4VX4nL6Z1sa3IrL1tw_LGKJX9ME72LcJiNpug
You are very WIMSEcal!
```

You can also run cURL against the server and see the error message:
```
curl -v http://localhost:8080/
```

## Running the demo with Cloudflare as "middlebox"

Follow the above instructions but when running the server.

We will also run cloudflared to proxy the requests to cloudflare's "TLS removed and added here" service:
```
docker run --net=host --rm cloudflare/cloudflared:latest tunnel --no-autoupdate --url "http://localhost:8080"
```

This will give you an `xxx.trycloudflare.com` URL (without account!).

You can then run the client against that URL:
```
go run ./examples/wimse-9421-client demo.go https://xxx.trycloudflare.com
```

You will notice Cloudflare modified the response adding its own headers but the signature on the headers and body we wanted to have signed is still valid and the client accepts the response. Guaranteeing us end to end integrity and authenticity of the message.
