package mitmproxy

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

type CAOptions struct {
	Name         string
	Organization string
	Validity     time.Duration
}

// NewCA creates a new CA certificate and associated private key.
func NewCA(optFns ...func(*CAOptions)) (*x509.Certificate, *rsa.PrivateKey, error) {
	options := CAOptions{
		Name:         "mitmproxy ca",
		Organization: "mitmproxy",
		Validity:     24 * time.Hour,
	}

	for _, fn := range optFns {
		fn(&options)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pub := priv.Public()

	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   options.Name,
			Organization: []string{options.Organization},
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-options.Validity),
		NotAfter:              time.Now().Add(options.Validity),
		DNSNames:              []string{options.Name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

func LoadCA(certFile, keyFile string) (*x509.Certificate, crypto.PrivateKey, error) {
	ca, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	return caCert, ca.PrivateKey, nil
}

func LoadOrCreateCA(certFile, keyFile string, optFns ...func(*CAOptions)) (*x509.Certificate, crypto.PrivateKey, error) {
	if caCert, privKey, err := LoadCA(certFile, keyFile); err == nil {
		return caCert, privKey, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	caCert, privKey, err := NewCA(optFns...)
	if err != nil {
		return nil, nil, err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open cert file for writing: %w", err)
	}
	defer certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open key file for writing: %w", err)
	}
	defer keyOut.Close()

	if eerr := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}); eerr != nil {
		return nil, nil, fmt.Errorf("cannot write CA certificate to disk: %w", eerr)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot convert private key to DER format: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("cannot write CA key to disk: %w", err)
	}

	return caCert, privKey, nil
}

type certHandler struct {
	cert []byte
}

// NewCertHandler returns an http.Handler that will present the client
// with the CA certificate to use in browser.
func NewCertHandler(ca *x509.Certificate) http.Handler {
	return &certHandler{
		cert: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Raw,
		}),
	}
}

// ServeHTTP writes the CA certificate in PEM format to the client.
func (h *certHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/x-x509-ca-cert")
	_, _ = rw.Write(h.cert)
}
