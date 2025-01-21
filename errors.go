package kmskey

import "errors"

var (
	ErrKeyNotSignVerifyError        = errors.New("key usage is not SIGN_VERIFY")
	ErrKeyNotEncryptDecryptError    = errors.New("key usage is not ENCRYPT_DECRYPT")
	ErrNoAwsClientError             = errors.New("no aws client initialized, use WithAwsConfig or WithAwsClient")
	ErrInvalidSigningAlgorithmError = errors.New("invalid signing algorithm choice")
	ErrUnsupportedDecryptionError   = errors.New("unsupported decryption options")
)
