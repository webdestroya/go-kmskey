package kmscertsigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Key struct {
	keyArn string
	client awsClienter
	ctx    context.Context

	grantTokens []string

	signingAlg  kmsTypes.SigningAlgorithmSpec
	signingAlgs []kmsTypes.SigningAlgorithmSpec
	keySpec     kmsTypes.KeySpec
	keyUsage    kmsTypes.KeyUsageType

	encryptionAlg  kmsTypes.EncryptionAlgorithmSpec
	encryptionAlgs []kmsTypes.EncryptionAlgorithmSpec

	keyIdBytes []byte

	pubKey crypto.PublicKey
}

var (
	_ crypto.Signer    = (*Key)(nil)
	_ crypto.Decrypter = (*Key)(nil)
	_ realPrivateKey   = (*Key)(nil)
)

func NewKey(ctx context.Context, keyArn string, opts ...optionFunc) (*Key, error) {

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

func (k *Key) SigningAlgorithms() []kmsTypes.SigningAlgorithmSpec {
	return k.signingAlgs
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

func (k *Key) KMSKeyId() string {
	return k.keyArn
}

func (k *Key) PublicKeyId() []byte {
	return nil
}

func (k *Key) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *Key) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if k.keyUsage != kmsTypes.KeyUsageTypeEncryptDecrypt {
		return nil, ErrKeyNotEncryptDecryptError
	}

	return nil, nil
}

func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	if k.keyUsage != kmsTypes.KeyUsageTypeSignVerify {
		return nil, ErrKeyNotSignVerifyError
	}

	alg := k.signingAlg

	if opts != nil {
		if alg == "" {
			alg = k.determineSigningAlgorithm(opts)
		}
	}

	if !slices.Contains(k.signingAlgs, alg) {
		return nil, fmt.Errorf("%w: invalid signature alg: %v", ErrInvalidSigningAlgorithmError, string(alg))
	}

	resp, err := k.client.Sign(k.ctx, &kms.SignInput{
		KeyId:            &k.keyArn,
		Message:          digest,
		SigningAlgorithm: alg,
		MessageType:      kmsTypes.MessageTypeDigest,
		GrantTokens:      k.grantTokens,
	})
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func (k *Key) determineSigningAlgorithm(opts crypto.SignerOpts) kmsTypes.SigningAlgorithmSpec {
	// RSA with PSS
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		switch pssOpts.Hash {
		case crypto.SHA256:
			return kmsTypes.SigningAlgorithmSpecRsassaPssSha256
		case crypto.SHA384:
			return kmsTypes.SigningAlgorithmSpecRsassaPssSha384
		case crypto.SHA512:
			return kmsTypes.SigningAlgorithmSpecRsassaPssSha512
		}
	}

	// it's an RSA key
	if _, ok := k.pubKey.(*rsa.PublicKey); ok {
		switch opts.HashFunc() {
		case crypto.SHA256:
			return kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case crypto.SHA384:
			return kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case crypto.SHA512:
			return kmsTypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		}
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		return kmsTypes.SigningAlgorithmSpecEcdsaSha256
	case crypto.SHA384:
		return kmsTypes.SigningAlgorithmSpecEcdsaSha384
	case crypto.SHA512:
		return kmsTypes.SigningAlgorithmSpecEcdsaSha512
	}

	// this will likely fail, but not much we can do
	return kmsTypes.SigningAlgorithmSpecEcdsaSha384
}
