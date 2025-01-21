package testutils

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"time"
)

func CertificateTemplate(parent *x509.Certificate, fnOpts ...func(*x509.Certificate)) *x509.Certificate {

	buf := make([]byte, 32)

	rand.Read(buf)

	subject := pkix.Name{
		CommonName: hex.EncodeToString(buf),
	}

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		Issuer:                subject,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
	}

	if parent == nil {
		cert.IsCA = true
		cert.KeyUsage = x509.KeyUsageCertSign
	} else {
		cert.KeyUsage = x509.KeyUsageDigitalSignature
		cert.SerialNumber = parent.SerialNumber.Add(parent.SerialNumber, big.NewInt(1))
	}

	for _, fnOpt := range fnOpts {
		fnOpt(cert)
	}

	return cert
}
