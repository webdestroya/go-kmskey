package kmskey

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

func (k *Key) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if k.keyUsage != kmsTypes.KeyUsageTypeEncryptDecrypt {
		return nil, ErrKeyNotEncryptDecryptError
	}

	oaepOpts, ok := opts.(*rsa.OAEPOptions)
	if !ok {
		return nil, fmt.Errorf("%w: only OAEP decryption is supported", ErrUnsupportedDecryptionError)
	}

	hsh := oaepOpts.MGFHash
	if hsh == 0 {
		hsh = oaepOpts.Hash
	}

	var encAlg kmsTypes.EncryptionAlgorithmSpec

	switch hsh {
	case crypto.SHA1:
		encAlg = kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha1
	case crypto.SHA256:
		encAlg = kmsTypes.EncryptionAlgorithmSpecRsaesOaepSha256
	default:

		return nil, fmt.Errorf("%w: unsupported hashing function", ErrUnsupportedDecryptionError)
	}

	if !slices.Contains(k.encryptionAlgs, encAlg) {
		return nil, fmt.Errorf("%w: unsupported hashing function: %v", ErrUnsupportedDecryptionError, encAlg)
	}

	resp, err := k.client.Decrypt(k.ctx, &kms.DecryptInput{
		CiphertextBlob:      msg,
		EncryptionAlgorithm: encAlg,
		GrantTokens:         k.grantTokens,
		KeyId:               &k.keyArn,
	})
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
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
