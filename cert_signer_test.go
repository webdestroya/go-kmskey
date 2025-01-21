package kmscertsigner_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/webdestroya/kmscertsigner"
	"github.com/webdestroya/kmscertsigner/internal/testutils"
	"github.com/webdestroya/kmscertsigner/internal/utils"
	"github.com/webdestroya/kmscertsigner/mocks/mocksigner"
)

func TestCertSigning(t *testing.T) {

	t.Parallel()

	tables := []struct {
		label   string
		privKey crypto.Signer
		sigAlg  x509.SignatureAlgorithm
	}{
		{
			label:   "ecc256",
			privKey: utils.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
		},
		{
			label:   "ecc384",
			privKey: utils.Must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)),
		},
		{
			label:   "ecc521",
			privKey: utils.Must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader)),
		},

		{
			label:   "rsa2048",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
		},
		{
			label:   "rsa3072",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 3072)),
		},
		{
			label:   "rsa4096",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 4096)),
		},

		{
			label:   "rsa2048pss256",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA256WithRSAPSS,
		},
		{
			label:   "rsa2048pss384",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA384WithRSAPSS,
		},
		{
			label:   "rsa2048pss512",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA512WithRSAPSS,
		},

		{
			label:   "rsa2048sha256",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA256WithRSA,
		},
		{
			label:   "rsa2048sha384",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA384WithRSA,
		},
		{
			label:   "rsa2048sha512",
			privKey: utils.Must(rsa.GenerateKey(rand.Reader, 2048)),
			sigAlg:  x509.SHA512WithRSA,
		},
	}

	for _, table := range tables {
		t.Run(table.label, func(t *testing.T) {

			client := mocksigner.NewMockSignerClient(t, table.privKey)

			key, err := kmscertsigner.New(context.Background(), "alias/blah", kmscertsigner.WithAwsClient(client))
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
