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
