# Go KMS Certificate Signer

[![API Reference](https://pkg.go.dev/badge/github.com/webdestroya/go-kmskey)](https://pkg.go.dev/github.com/webdestroya/go-kmskey?tab=doc)
[![Go Report Card](https://goreportcard.com/badge/github.com/webdestroya/go-kmskey)](https://goreportcard.com/report/github.com/webdestroya/go-kmskey)
[![GitHub License](https://img.shields.io/github/license/webdestroya/go-kmskey)](LICENSE)

This library will allow you to use AWS KMS keys to sign X509 certificates.

## Install

```
go get -u github.com/webdestroya/go-kmskey@latest
```

## Features
* [Sign X509 Certificates using KMS Keys](#certificate-signing)
* Decrypt data using a KMS key
* Use KMS to generate secure random data

## Usage

### Certificate Signing

```go
package myapp

import (
  "context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/webdestroya/go-kmskey"
)

func main() {
  ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		panic(err)
	}

  key, err := kmskey.NewKey(ctx, "alias/my-signing-key", kmskey.WithAwsConfig(cfg))
  if err != nil {
    panic(err)
  }

  subject := pkix.Name{
		CommonName: `My Custom Certificate Authority`,
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
    IsCA:                  true,
    MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

  certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
  if err != nil {
    panic(err)
  }

  certificate, err := x509.ParseCertificate(certBytes)
  if err != nil {
    panic(err)
  }

  // You can do something with the certificate now, like sign other leaf certificates

}
```

### Secure Random Data
```go
package myapp

import (
	"context"
	"crypto/rsa"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/webdestroya/go-kmskey"
)

func Example() {

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		panic(err)
	}

	kmsrand, err := kmskey.NewRandom(ctx, kmskey.WithAwsConfig(cfg))
  if err != nil {
    panic(err)
  }

	// Key Generation:
	rsaKey, err := rsa.GenerateKey(kmsrand, 3072)
	if err != nil {
		panic(err)
	}

	// do something with the new key
	_ = rsaKey

}

```


## License

Licensed under the MIT License. See [LICENSE](LICENSE) for more info.