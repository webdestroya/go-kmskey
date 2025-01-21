package mocksigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

const (
	defaultKeyArn = `arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-deadbeefdead`
	randData      = `_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
)

type MockSignerClient struct {
	t        *testing.T
	reqNum   atomic.Uint32
	privKey  crypto.Signer
	keyUsage kmsTypes.KeyUsageType
}

func (m *MockSignerClient) PrivateKey() crypto.Signer {
	return m.privKey
}

func (m *MockSignerClient) Public() crypto.PublicKey {
	return m.privKey.Public()
}

func (m *MockSignerClient) GenerateRandom(ctx context.Context, input *kms.GenerateRandomInput, _ ...func(*kms.Options)) (*kms.GenerateRandomOutput, error) {
	bufLen := int(*input.NumberOfBytes)
	pos := m.reqNum.Add(uint32(1))

	return &kms.GenerateRandomOutput{
		Plaintext: bytes.Repeat([]byte{randData[pos]}, bufLen),
	}, nil
}

func (m *MockSignerClient) Decrypt(ctx context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {

	rsaKey, ok := m.privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, &kmsTypes.InvalidKeyUsageException{}
	}

	var (
		res []byte
		err error
	)

	switch input.EncryptionAlgorithm {
	case kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha1:
		res, err = rsaKey.Decrypt(rand.Reader, input.CiphertextBlob, &rsa.OAEPOptions{
			Hash: crypto.SHA1,
		})

	case kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha256:
		res, err = rsaKey.Decrypt(rand.Reader, input.CiphertextBlob, &rsa.OAEPOptions{
			Hash: crypto.SHA256,
		})

	default:
		return nil, &kmsTypes.InvalidKeyUsageException{}
	}

	if err != nil {
		return nil, err
	}

	return &kms.DecryptOutput{
		EncryptionAlgorithm: input.EncryptionAlgorithm,
		KeyId:               aws.String(defaultKeyArn),
		Plaintext:           res,
	}, nil

}

func (m *MockSignerClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {

	pub := m.privKey.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	out := &kms.GetPublicKeyOutput{
		KeyId:     aws.String(defaultKeyArn),
		KeySpec:   "",
		KeyUsage:  m.keyUsage,
		PublicKey: pubBytes,
	}

	if m.keyUsage == kmsTypes.KeyUsageTypeEncryptDecrypt {
		switch v := m.privKey.(type) {
		case *rsa.PrivateKey:
			out.KeySpec = kmsTypes.KeySpec(fmt.Sprintf("RSA_%d", v.Size()*8))
			out.EncryptionAlgorithms = []kmsTypes.EncryptionAlgorithmSpec{
				kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha1,
				kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha256,
			}
		default:
			return nil, &kmsTypes.KMSInternalException{
				Message: aws.String("EncryptDecrypt is only for RSA keys"),
			}
		}
	} else {

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

type optionFunc = func(*MockSignerClient)

func NewMockSignerClient(t *testing.T, key crypto.Signer, optFns ...optionFunc) *MockSignerClient {
	m := &MockSignerClient{
		t:        t,
		privKey:  key,
		reqNum:   atomic.Uint32{},
		keyUsage: kmsTypes.KeyUsageTypeSignVerify,
	}

	for _, optFn := range optFns {
		optFn(m)
	}

	return m
}

func WithKeyUsage(v kmsTypes.KeyUsageType) optionFunc {
	return func(m *MockSignerClient) {
		m.keyUsage = v
	}
}

func WithRSAKey(bits int) optionFunc {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return func(m *MockSignerClient) {
		m.privKey = key
	}
}

func WithECCKey(curve elliptic.Curve) optionFunc {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return func(m *MockSignerClient) {
		m.privKey = key
	}
}

func NewMockEncryptDecrypt(t *testing.T, bitSize int, opts ...optionFunc) *MockSignerClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	if opts == nil {
		opts = make([]optionFunc, 0)
	}

	opts = append(opts, WithKeyUsage(kmsTypes.KeyUsageTypeEncryptDecrypt))

	return NewMockSignerClient(t, key, opts...)
}

func NewMockRandom(t *testing.T) *MockSignerClient {
	return NewMockSignerClient(t, nil)
}
