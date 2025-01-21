package kmscertsigner

import "errors"

var (
	ErrKeyNotSignVerifyError        = errors.New("KMS Key is not SIGN_VERIFY usage")
	ErrNoAwsClientError             = errors.New("no aws client initialized. Use WithAwsConfig or WithAwsClient")
	ErrInvalidSigningAlgorithmError = errors.New("invalid signing algorithm choice")
)
