package kmskey

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Key struct {
	keyArn string
	client kmsClienter
	ctx    context.Context

	grantTokens []string

	signingAlg  kmsTypes.SigningAlgorithmSpec
	signingAlgs []kmsTypes.SigningAlgorithmSpec
	keySpec     kmsTypes.KeySpec
	keyUsage    kmsTypes.KeyUsageType

	encryptionAlgs []kmsTypes.EncryptionAlgorithmSpec

	pubKeyBytes []byte

	pubKey crypto.PublicKey
}

var (
	_ crypto.Signer     = (*Key)(nil)
	_ crypto.Decrypter  = (*Key)(nil)
	_ crypto.PrivateKey = (*Key)(nil)
	_ realPrivateKey    = (*Key)(nil)
)

func NewKey(ctx context.Context, keyArn string, opts ...OptionFunc) (*Key, error) {

	options := kcsOption{}

	for _, fn := range opts {
		if err := fn(&options); err != nil {
			return nil, err
		}
	}

	if options.awsClient == nil {
		return nil, ErrNoAwsClientError
	}

	key := &Key{
		ctx:        ctx,
		client:     options.awsClient,
		signingAlg: options.signingAlg,
	}
	if err := key.preload(keyArn); err != nil {
		return nil, err
	}

	return key, nil
}

func (k *Key) KeySpec() kmsTypes.KeySpec {
	return k.keySpec
}

func (k *Key) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*Key)
	if !ok {
		return false
	}

	return k.keyArn == xx.keyArn
}

// The resolved ARN of the key being used
func (k *Key) KeyARN() string {
	return k.keyArn
}

// The value is a DER-encoded X.509 public key, also known as SubjectPublicKeyInfo (SPKI), as defined in RFC 5280
func (k *Key) SubjectPublicKeyInfo() []byte {
	return k.pubKeyBytes
}

func (k *Key) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *Key) preload(keyArn string) error {
	resp, err := k.client.GetPublicKey(k.ctx, &kms.GetPublicKeyInput{
		KeyId:       &keyArn,
		GrantTokens: k.grantTokens,
	})
	if err != nil {
		return err
	}

	k.keyArn = *resp.KeyId
	k.keySpec = resp.KeySpec
	k.keyUsage = resp.KeyUsage
	k.pubKeyBytes = resp.PublicKey

	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return err
	}
	k.pubKey = pub

	switch k.keyUsage {
	case kmsTypes.KeyUsageTypeEncryptDecrypt:
		k.encryptionAlgs = resp.EncryptionAlgorithms

	case kmsTypes.KeyUsageTypeSignVerify:
		k.signingAlgs = resp.SigningAlgorithms
		if k.signingAlg == "" && len(k.signingAlgs) == 1 {
			k.signingAlg = k.signingAlgs[0]
		}
	}

	return nil
}
