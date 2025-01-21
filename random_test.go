package kmskey_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/webdestroya/go-kmskey"
	"github.com/webdestroya/go-kmskey/mocks/mockkms"
)

// func FuzzRead(f *testing.F) {
// 	for _, seed := range []int{1, 256, 512, 1024, 2048, 2049, 2050, 2047, 10240} {
// 		f.Add(seed)
// 	}

// 	f.Fuzz(func(t *testing.T, a int) {
// 		validateResponse(t, a)
// 	})
// }

func TestRead(t *testing.T) {

	tables := []struct {
		size int
	}{
		{1},
		{256},
		{512},
		{1024},
		{2048},
		{2049},
		{2050},
		{3060},
	}

	for _, table := range tables {
		t.Run(fmt.Sprintf("size_%d", table.size), func(t *testing.T) {
			validateResponse(t, table.size)
		})
	}

	t.Run("zero", func(t *testing.T) {
		m := mockkms.NewMockRandom(t)
		rando, err := kmskey.NewRandom(context.Background(), kmskey.WithAwsClient(m))
		require.NoError(t, err)

		n, err := rando.Read(nil)
		require.NoError(t, err)
		require.Zero(t, n)

		n, err = rando.Read([]byte{})
		require.NoError(t, err)
		require.Zero(t, n)

	})

	t.Run("chunks", func(t *testing.T) {
		resp := validateResponse(t, (1024*24)+100)

		counter := make(map[byte]int)

		for _, chr := range resp {
			counter[chr] += 1
		}

		tot1024 := 0
		totOther := 0

		for _, num := range counter {
			if num == 1024 {
				tot1024 += 1
			} else {
				totOther += 1
			}
		}

		require.Equal(t, 24, tot1024)
		require.Equal(t, 1, totOther)

	})

	t.Run("invalid setup", func(t *testing.T) {
		res, err := kmskey.NewRandom(context.Background())
		require.Error(t, err)
		require.ErrorIs(t, err, kmskey.ErrNoAwsClientError)
		require.Nil(t, res)
	})

}

func validateResponse(t *testing.T, size int) []byte {
	t.Helper()
	m := mockkms.NewMockRandom(t)
	rando, err := kmskey.NewRandom(context.Background(), kmskey.WithAwsClient(m))
	require.NoError(t, err)

	buf := bytes.Repeat([]byte(`!`), size)

	n, err := rando.Read(buf)

	require.NoError(t, err)
	require.Equal(t, size, n)
	require.NotContains(t, string(buf), `!`)

	return buf
}
