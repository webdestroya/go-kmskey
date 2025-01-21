package kmscertsigner

import "errors"

var (
	ErrKeyNotSignVerifyError        = errors.New("KMS Key usage is not SIGN_VERIFY")
	ErrKeyNotEncryptDecryptError    = errors.New("KMS Key usage is not ENCRYPT_DECRYPT")
	ErrNoAwsClientError             = errors.New("no aws client initialized. Use WithAwsConfig or WithAwsClient")
	ErrInvalidSigningAlgorithmError = errors.New("invalid signing algorithm choice")
)
