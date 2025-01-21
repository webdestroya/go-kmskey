package kmskey_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/webdestroya/go-kmskey"
	"github.com/webdestroya/go-kmskey/mocks/mockkms"
)

func TestDecrypt(t *testing.T) {
	client := mockkms.NewMockEncryptDecrypt(t, 2048)
	rsaKey := client.PrivateKey().(*rsa.PrivateKey)

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
