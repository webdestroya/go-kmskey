package rand

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type optionFunc = func(*kmsRand)

func WithAwsClient(client awsClienter) optionFunc {
	return func(r *kmsRand) {
		r.client = client
	}
}

func WithAwsConfig(cfg aws.Config, fns ...func(*kms.Options)) optionFunc {
	return func(r *kmsRand) {
		r.client = kms.NewFromConfig(cfg, fns...)
	}
}

func WithCustomKeyStoreId(v string) optionFunc {
	return func(r *kmsRand) {
		r.customKeyStoreId = &v
	}
}
