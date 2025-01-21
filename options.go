package kmscertsigner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kcsOption struct {
	awsClient   awsClienter
	signingAlg  kmsTypes.SigningAlgorithmSpec
	grantTokens []string
}

type CertSignerOpt func(*kcsOption) error

type awsClienter interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

func WithAwsClient(client awsClienter) CertSignerOpt {
	return func(kcs *kcsOption) error {
		kcs.awsClient = client
		return nil
	}
}

func WithAwsConfig(cfg aws.Config, fns ...func(*kms.Options)) CertSignerOpt {
	return func(kcs *kcsOption) error {
		kcs.awsClient = kms.NewFromConfig(cfg, fns...)
		return nil
	}
}

func WithSigningAlgorithm(alg kmsTypes.SigningAlgorithmSpec) CertSignerOpt {
	return func(ko *kcsOption) error {
		ko.signingAlg = alg
		return nil
	}
}

func WithGrantTokens(tokens []string) CertSignerOpt {
	return func(ko *kcsOption) error {
		ko.grantTokens = tokens
		return nil
	}
}
