package rand_test

import (
	"context"
	"crypto/rsa"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/webdestroya/kmskey/rand"
)

func Example() {

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-fake-1"))
	if err != nil {
		panic(err)
	}

	kmsrand := rand.New(ctx, rand.WithAwsConfig(cfg))

	// Key Generation:
	rsaKey, err := rsa.GenerateKey(kmsrand, 3072)
	if err != nil {
		panic(err)
	}

	// do something with the new key
	_ = rsaKey

}
