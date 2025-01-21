package kmskey

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

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
