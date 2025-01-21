package kmskey_test

import (
	"context"
	"crypto/rsa"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/webdestroya/go-kmskey"
)

func ExampleNewRandom() {

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-fake-1"))
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
