package kmskey

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kcsOption struct {
	awsClient        kmsClienter
	signingAlg       kmsTypes.SigningAlgorithmSpec
	grantTokens      []string
	maxConcurrency   int
	customKeyStoreId *string
}

type OptionFunc = func(*kcsOption) error

// Used with [NewKey] and [NewRandom]
func WithAwsClient(client kmsClienter) OptionFunc {
	return func(kcs *kcsOption) error {
		kcs.awsClient = client
		return nil
	}
}

// Used with [NewKey] and [NewRandom]
func WithAwsConfig(cfg aws.Config, fns ...func(*kms.Options)) OptionFunc {
	return func(kcs *kcsOption) error {
		kcs.awsClient = kms.NewFromConfig(cfg, fns...)
		return nil
	}
}

// Force the signing algorithm to use. You probably should not set this.
func WithSigningAlgorithm(alg kmsTypes.SigningAlgorithmSpec) OptionFunc {
	return func(ko *kcsOption) error {
		ko.signingAlg = alg
		return nil
	}
}

// If you need to provide KMS grant tokens for your requests to
// GetPublicKey, Sign, Decrypt
func WithGrantTokens(tokens []string) OptionFunc {
	return func(ko *kcsOption) error {
		ko.grantTokens = tokens
		return nil
	}
}

// Specifies a Custom KeyStore to use to generate random data.
//
// Only used with [NewRandom]
func WithCustomKeyStoreId(v string) OptionFunc {
	return func(r *kcsOption) error {
		r.customKeyStoreId = &v
		return nil
	}
}

// Sets the maximum parallel requests that will be made to get random data.
//
// Only used with [NewRandom]
func WithMaxConcurrency(conc int) OptionFunc {
	return func(r *kcsOption) error {
		r.maxConcurrency = conc
		return nil
	}
}
