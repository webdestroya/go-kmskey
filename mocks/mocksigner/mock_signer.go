package mocksigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const defaultKeyArn = `arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-deadbeefdead`

type MockSignerClient struct {
	t        *testing.T
	privKey  crypto.Signer
	keyUsage kmsTypes.KeyUsageType
}

func (m *MockSignerClient) Public() crypto.PublicKey {
	return m.privKey.Public()
}

func (m *MockSignerClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {

	pub := m.privKey.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	out := &kms.GetPublicKeyOutput{
		KeyId:             aws.String(defaultKeyArn),
		KeySpec:           "",
		KeyUsage:          m.keyUsage,
		PublicKey:         pubBytes,
		SigningAlgorithms: []kmsTypes.SigningAlgorithmSpec{},
	}

	switch v := m.privKey.(type) {
	case *rsa.PrivateKey:
		out.KeySpec = kmsTypes.KeySpec(fmt.Sprintf("RSA_%d", v.Size()*8))
		out.SigningAlgorithms = []kmsTypes.SigningAlgorithmSpec{
			kmsTypes.SigningAlgorithmSpecRsassaPssSha256,
			kmsTypes.SigningAlgorithmSpecRsassaPssSha384,
			kmsTypes.SigningAlgorithmSpecRsassaPssSha512,
			kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		}

	case *ecdsa.PrivateKey:
		switch v.Curve {
		case elliptic.P256():
			out.KeySpec = kmsTypes.KeySpecEccNistP256
			out.SigningAlgorithms = []kmsTypes.SigningAlgorithmSpec{
				kmsTypes.SigningAlgorithmSpecEcdsaSha256,
			}

		case elliptic.P384():
			out.KeySpec = kmsTypes.KeySpecEccNistP384
			out.SigningAlgorithms = []kmsTypes.SigningAlgorithmSpec{
				kmsTypes.SigningAlgorithmSpecEcdsaSha384,
			}

		case elliptic.P521():
			out.KeySpec = kmsTypes.KeySpecEccNistP521
			out.SigningAlgorithms = []kmsTypes.SigningAlgorithmSpec{
				kmsTypes.SigningAlgorithmSpecEcdsaSha512,
			}
		}

	default:
		return nil, &kmsTypes.KMSInternalException{
			Message: aws.String(fmt.Sprintf("BAD KEY TYPE: %T", v)),
		}
	}

	return out, nil
}

func (m *MockSignerClient) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {

	out := &kms.SignOutput{
		KeyId:            aws.String(defaultKeyArn),
		SigningAlgorithm: input.SigningAlgorithm,
	}

	var (
		signature []byte
		err       error
	)

	switch input.SigningAlgorithm {
	case kmsTypes.SigningAlgorithmSpecRsassaPssSha256:
		signature, err = m.privKey.(*rsa.PrivateKey).Sign(rand.Reader, input.Message, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		// signature, err = rsa.SignPSS(rand.Reader, m.privKey.(*rsa.PrivateKey), crypto.SHA256, input.Message, nil)

	case kmsTypes.SigningAlgorithmSpecRsassaPssSha384:
		// signature, err = rsa.SignPSS(rand.Reader, m.privKey.(*rsa.PrivateKey), crypto.SHA384, input.Message, nil)
		signature, err = m.privKey.(*rsa.PrivateKey).Sign(rand.Reader, input.Message, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA384,
		})

	case kmsTypes.SigningAlgorithmSpecRsassaPssSha512:
		signature, err = m.privKey.(*rsa.PrivateKey).Sign(rand.Reader, input.Message, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA512,
		})

	case kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		signature, err = rsa.SignPKCS1v15(rand.Reader, m.privKey.(*rsa.PrivateKey), crypto.SHA256, input.Message)

	case kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		signature, err = rsa.SignPKCS1v15(rand.Reader, m.privKey.(*rsa.PrivateKey), crypto.SHA384, input.Message)

	case kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		signature, err = rsa.SignPKCS1v15(rand.Reader, m.privKey.(*rsa.PrivateKey), crypto.SHA512, input.Message)

	case kmsTypes.SigningAlgorithmSpecEcdsaSha256:
		signature, err = m.privKey.Sign(rand.Reader, input.Message, crypto.SHA256)
	case kmsTypes.SigningAlgorithmSpecEcdsaSha384:
		signature, err = m.privKey.Sign(rand.Reader, input.Message, crypto.SHA384)
	case kmsTypes.SigningAlgorithmSpecEcdsaSha512:
		signature, err = m.privKey.Sign(rand.Reader, input.Message, crypto.SHA512)
	}

	if err != nil {
		return nil, &kmsTypes.KMSInternalException{
			Message: aws.String(err.Error()),
		}
	}

	out.Signature = signature

	return out, nil
}

type OptionFunc = func(*MockSignerClient)

func NewMockSignerClient(t *testing.T, key crypto.Signer, optFns ...OptionFunc) *MockSignerClient {
	m := &MockSignerClient{
		t:        t,
		privKey:  key,
		keyUsage: kmsTypes.KeyUsageTypeSignVerify,
	}

	for _, optFn := range optFns {
		optFn(m)
	}

	return m
}

func WithKeyUsage(v kmsTypes.KeyUsageType) OptionFunc {
	return func(m *MockSignerClient) {
		m.keyUsage = v
	}
}
