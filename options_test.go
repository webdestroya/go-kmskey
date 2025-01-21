package kmscertsigner

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/require"
)

var _ awsClienter = (*kms.Client)(nil)

func TestWithSigningAlgorithm(t *testing.T) {
	o := kcsOption{}
	require.Empty(t, o.signingAlg)
	err := WithSigningAlgorithm(kmsTypes.SigningAlgorithmSpecEcdsaSha384)(&o)
	require.NoError(t, err)
	require.Equal(t, kmsTypes.SigningAlgorithmSpecEcdsaSha384, o.signingAlg)
}

func TestWithGrantTokens(t *testing.T) {
	o := kcsOption{}
	require.Empty(t, o.grantTokens)
	err := WithGrantTokens([]string{"a", "b", "c"})(&o)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, o.grantTokens)
}

func TestWithAwsConfig(t *testing.T) {
	o := kcsOption{}
	require.Empty(t, o.awsClient)

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-fake-1"))
	require.NoError(t, err)

	err = WithAwsConfig(cfg)(&o)
	require.NoError(t, err)

	opts := o.awsClient.(*kms.Client).Options()
	require.Equal(t, "us-fake-1", opts.Region)
}
