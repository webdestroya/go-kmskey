package kmskey

import (
	"crypto/rsa"
	"hash"
	"io"

	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func (k *Key) Encrypt(hsh hash.Hash, rand io.Reader, msg []byte) ([]byte, error) {
	if k.keyUsage != kmsTypes.KeyUsageTypeEncryptDecrypt {
		return nil, ErrKeyNotEncryptDecryptError
	}

	rsaPub, ok := k.pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedDecryptionError
	}

	return rsa.EncryptOAEP(hsh, rand, rsaPub, msg, nil)

}
