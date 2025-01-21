package kmskey

import (
	"context"
	"crypto"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type realPrivateKey interface {
	Public() crypto.PublicKey
	Equal(crypto.PrivateKey) bool
}

type kmsClienter interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateRandom(context.Context, *kms.GenerateRandomInput, ...func(*kms.Options)) (*kms.GenerateRandomOutput, error)
}
