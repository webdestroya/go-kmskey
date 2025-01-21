package kmskey_test

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/webdestroya/go-kmskey"
	"github.com/webdestroya/go-kmskey/internal/testutils"
	"github.com/webdestroya/go-kmskey/mocks/mockkms"
)

func TestCertSigning(t *testing.T) {

	t.Parallel()

	tables := []struct {
		label  string
		keyOpt mockkms.OptionFunc
		sigAlg x509.SignatureAlgorithm
	}{
		{
			label:  "ecc256",
			keyOpt: mockkms.WithECCKey(elliptic.P256()),
		},
		{
			label:  "ecc384",
			keyOpt: mockkms.WithECCKey(elliptic.P384()),
		},
		{
			label:  "ecc521",
			keyOpt: mockkms.WithECCKey(elliptic.P521()),
		},

		{
			label:  "rsa2048",
			keyOpt: mockkms.WithRSAKey(2048),
		},
		{
			label:  "rsa3072",
			keyOpt: mockkms.WithRSAKey(3072),
		},
		{
			label:  "rsa4096",
			keyOpt: mockkms.WithRSAKey(4096),
		},

		{
			label:  "rsa2048pss256",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA256WithRSAPSS,
		},
		{
			label:  "rsa2048pss384",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA384WithRSAPSS,
		},
		{
			label:  "rsa2048pss512",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA512WithRSAPSS,
		},

		{
			label:  "rsa2048sha256",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA256WithRSA,
		},
		{
			label:  "rsa2048sha384",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA384WithRSA,
		},
		{
			label:  "rsa2048sha512",
			keyOpt: mockkms.WithRSAKey(2048),
			sigAlg: x509.SHA512WithRSA,
		},
	}

	for _, table := range tables {
		t.Run(table.label, func(t *testing.T) {

			client := mockkms.NewMockSignerClient(t, table.keyOpt)

			key, err := kmskey.NewKey(context.Background(), "alias/blah", kmskey.WithAwsClient(client))
			require.NoError(t, err)

			opts := make([]func(*x509.Certificate), 0)

			if table.sigAlg != x509.UnknownSignatureAlgorithm {
				opts = append(opts, func(c *x509.Certificate) {
					c.SignatureAlgorithm = table.sigAlg
				})
			}

			certReq := testutils.CertificateTemplate(nil, func(c *x509.Certificate) {
				// c.AuthorityKeyId = key.Public()
			})

			certBytes, err := x509.CreateCertificate(rand.Reader, certReq, certReq, key.Public(), key)
			require.NoError(t, err)

			cert, err := x509.ParseCertificate(certBytes)
			require.NoError(t, err)

			require.NoError(t, cert.CheckSignatureFrom(cert))

			t.Logf("CAPUBKEY: %v", hex.EncodeToString(cert.SubjectKeyId))
			t.Logf("CAAuthKey: %v", hex.EncodeToString(cert.AuthorityKeyId))

			childReq := testutils.CertificateTemplate(cert, opts...)
			childBytes, err := x509.CreateCertificate(rand.Reader, childReq, certReq, key.Public(), key)
			require.NoError(t, err)

			childCert, err := x509.ParseCertificate(childBytes)
			require.NoError(t, err)

			if table.sigAlg != x509.UnknownSignatureAlgorithm {
				require.Equal(t, table.sigAlg, childCert.SignatureAlgorithm)
			}

			t.Logf("PUBKEY: %v", hex.EncodeToString(childCert.SubjectKeyId))
			t.Logf("AuthKey: %v", hex.EncodeToString(childCert.AuthorityKeyId))

			require.NoError(t, childCert.CheckSignatureFrom(cert))

		})
	}
}
