package kmskey

import (
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/sync/errgroup"
)

type Rand interface {
	io.Reader
	GetCustomKeyStoreId() *string
}

const (
	maxRandomBytes        = 1024
	defaultMaxConcurrency = 10
)

type kmsRand struct {
	ctx    context.Context
	client kmsClienter

	customKeyStoreId *string
	maxConcurrency   int
}

var (
	_ io.Reader = (*kmsRand)(nil)
	_ Rand      = (*kmsRand)(nil)
)

func (k *kmsRand) Read(b []byte) (int, error) {

	numBytes := len(b)

	if numBytes == 0 {
		return 0, nil
	}

	// if k.client == nil {
	// 	return 0, errors.New("aws client not provided")
	// }

	// they want less than the limit
	if numBytes <= maxRandomBytes {
		buf, err := k.read(k.ctx, numBytes)
		if err != nil {
			return 0, err
		}
		return copy(b, buf), nil
	}

	loopCt := numBytes / maxRandomBytes
	if numBytes%maxRandomBytes != 0 {
		loopCt += 1
	}

	eg, ctx := errgroup.WithContext(k.ctx)
	eg.SetLimit(k.maxConcurrency)

	for i := 0; i < loopCt; i++ {
		eg.Go(func() error {

			bytesToGet := maxRandomBytes
			if (i+1)*maxRandomBytes > numBytes {
				bytesToGet = numBytes - (i * maxRandomBytes)
			}

			data, err := k.read(ctx, bytesToGet)
			if err != nil {
				return err
			}

			copy(b[i*maxRandomBytes:(i*maxRandomBytes)+bytesToGet], data)

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return 0, err
	}

	return numBytes, nil
}

func (k *kmsRand) read(ctx context.Context, numBytes int) ([]byte, error) {
	resp, err := k.client.GenerateRandom(ctx, &kms.GenerateRandomInput{
		CustomKeyStoreId: k.customKeyStoreId,
		NumberOfBytes:    aws.Int32(int32(numBytes)), //nolint:gosec // an overflow would just cause an AWS error, it's fine
	})
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}

func (k *kmsRand) GetCustomKeyStoreId() *string {
	return k.customKeyStoreId
}

func NewRandom(ctx context.Context, optFns ...OptionFunc) (Rand, error) {
	opts := kcsOption{
		maxConcurrency: defaultMaxConcurrency,
	}

	for _, optFn := range optFns {
		if err := optFn(&opts); err != nil {
			return nil, err
		}
	}

	r := &kmsRand{
		ctx:              ctx,
		client:           opts.awsClient,
		maxConcurrency:   opts.maxConcurrency,
		customKeyStoreId: opts.customKeyStoreId,
	}

	if r.client == nil {
		return nil, errors.New("aws client not provided")
	}

	return r, nil
}
