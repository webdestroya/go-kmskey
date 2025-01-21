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

type CertSigner interface {
	crypto.Signer
	KMSKeyId() string
	PublicKeyId() []byte

	SigningAlgorithms() []kmsTypes.SigningAlgorithmSpec
	KeySpec() kmsTypes.KeySpec
}

type kmsCertSigner struct {
	keyArn string
	client awsClienter
	ctx    context.Context

	grantTokens []string

	signingAlg  kmsTypes.SigningAlgorithmSpec
	signingAlgs []kmsTypes.SigningAlgorithmSpec
	keySpec     kmsTypes.KeySpec

	keyIdBytes []byte

	pubKey crypto.PublicKey
}

var _ CertSigner = (*kmsCertSigner)(nil)
var _ crypto.Signer = (*kmsCertSigner)(nil)

func New(ctx context.Context, keyArn string, opts ...CertSignerOpt) (CertSigner, error) {

	options := kcsOption{}

	for _, fn := range opts {
		if err := fn(&options); err != nil {
			return nil, err
		}
	}

	if options.awsClient == nil {
		return nil, ErrNoAwsClientError
	}

	key := &kmsCertSigner{
		ctx:        ctx,
		client:     options.awsClient,
		signingAlg: options.signingAlg,
	}
	if err := key.preload(keyArn); err != nil {
		return nil, err
	}

	return key, nil
}

func (k *kmsCertSigner) SigningAlgorithms() []kmsTypes.SigningAlgorithmSpec {
	return k.signingAlgs
}

func (k *kmsCertSigner) KeySpec() kmsTypes.KeySpec {
	return k.keySpec
}

func (k *kmsCertSigner) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*kmsCertSigner)
	if !ok {
		return false
	}

	return k.keyArn == xx.keyArn
}

func (k *kmsCertSigner) preload(keyArn string) error {
	resp, err := k.client.GetPublicKey(k.ctx, &kms.GetPublicKeyInput{
		KeyId:       &keyArn,
		GrantTokens: k.grantTokens,
	})
	if err != nil {
		return err
	}

	if resp.KeyUsage != kmsTypes.KeyUsageTypeSignVerify {
		return ErrKeyNotSignVerifyError
	}

	k.keyArn = *resp.KeyId
	k.signingAlgs = resp.SigningAlgorithms
	k.keySpec = resp.KeySpec

	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return err
	}
	k.pubKey = pub

	if k.signingAlg == "" && len(k.signingAlgs) == 1 {
		// k.signingAlg = getBestSigningAlgorithm(k.signingAlgs)
		k.signingAlg = k.signingAlgs[0]
	}

	return nil
}

func (k *kmsCertSigner) KMSKeyId() string {
	return k.keyArn
}

func (k *kmsCertSigner) PublicKeyId() []byte {
	return nil
}

func (k *kmsCertSigner) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *kmsCertSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

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

func (k *kmsCertSigner) determineSigningAlgorithm(opts crypto.SignerOpts) kmsTypes.SigningAlgorithmSpec {
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
