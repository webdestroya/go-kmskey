package kmscertsigner

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kcsOption struct {
	awsClient   awsClienter
	signingAlg  kmsTypes.SigningAlgorithmSpec
	grantTokens []string
}

type optionFunc = func(*kcsOption) error

func WithAwsClient(client awsClienter) optionFunc {
	return func(kcs *kcsOption) error {
		kcs.awsClient = client
		return nil
	}
}

func WithAwsConfig(cfg aws.Config, fns ...func(*kms.Options)) optionFunc {
	return func(kcs *kcsOption) error {
		kcs.awsClient = kms.NewFromConfig(cfg, fns...)
		return nil
	}
}

func WithSigningAlgorithm(alg kmsTypes.SigningAlgorithmSpec) optionFunc {
	return func(ko *kcsOption) error {
		ko.signingAlg = alg
		return nil
	}
}

func WithGrantTokens(tokens []string) optionFunc {
	return func(ko *kcsOption) error {
		ko.grantTokens = tokens
		return nil
	}
}
