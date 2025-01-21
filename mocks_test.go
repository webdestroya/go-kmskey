package rand_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	randData = `_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
)

type mockRandom struct {
	t      *testing.T
	reqNum atomic.Uint32
}

func (m *mockRandom) GenerateRandom(ctx context.Context, input *kms.GenerateRandomInput, _ ...func(*kms.Options)) (*kms.GenerateRandomOutput, error) {
	bufLen := int(*input.NumberOfBytes)
	pos := m.reqNum.Add(uint32(1))

	return &kms.GenerateRandomOutput{
		Plaintext: bytes.Repeat([]byte{randData[pos]}, bufLen),
	}, nil
}

func newMockRandom(t *testing.T) *mockRandom {
	t.Helper()

	return &mockRandom{
		t:      t,
		reqNum: atomic.Uint32{},
	}
}
