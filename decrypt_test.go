package kmskey_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
	"github.com/webdestroya/go-kmskey"
	"github.com/webdestroya/go-kmskey/internal/utils"
	"github.com/webdestroya/go-kmskey/mocks/mocksigner"
)

func TestDecrypt(t *testing.T) {
	rsaKey := utils.Must(rsa.GenerateKey(rand.Reader, 2048))
	client := mocksigner.NewMockSignerClient(t, rsaKey, mocksigner.WithKeyUsage(kmsTypes.KeyUsageTypeEncryptDecrypt))

	maxLen := rsaKey.PublicKey.Size() - 64 - 2
	t.Log(maxLen)

	key, err := kmskey.NewKey(context.Background(), "alias/blah", kmskey.WithAwsClient(client))
	require.NoError(t, err)

	input := make([]byte, maxLen)
	_, _ = rand.Read(input)

	encData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, input, nil)
	require.NoError(t, err)

	plaintext, err := key.Decrypt(nil, encData, &rsa.OAEPOptions{
		MGFHash: crypto.SHA256,
	})
	require.NoError(t, err)

	require.Equal(t, input, plaintext)

}
