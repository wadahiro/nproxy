package nproxy

import (
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"encoding/binary"

	crand "crypto/rand"

	"crypto"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	certCache   *certCache
}

type certCache struct {
	sm sync.Map
}

func (m *certCache) Load(host string) (*tls.Certificate, bool) {
	val, ok := m.sm.Load(host)
	if !ok {
		return nil, false
	}
	return val.(*tls.Certificate), true
}

func (m *certCache) Store(host string, cert *tls.Certificate) {
	m.sm.Store(host, cert)
}

func NewCertCache() *certCache {
	return &certCache{}
}

func NewCA(caCertPath, caKeyPath string) *CA {
	if caKeyPath == "" {
		log.Printf("debug: No CA mode.")
		return nil
	}

	ca, err := tls.LoadX509KeyPair(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("alert: Could not load key pair of CA: %v", err)
	}

	cert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatalf("alert: Invalid certificate : %v", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  ca.PrivateKey,
		certCache:   NewCertCache(),
	}
}

func (c *CA) FindOrCreateCert(host string) (*tls.Certificate, error) {
	cert, ok := c.certCache.Load(host)
	if ok {
		log.Printf("debug: Use cached cert : %s", host)

		// TODO: check expires and re-sign cert if expired
		return cert, nil
	}

	log.Printf("info: Signing cert for : %s", host)

	cert, err := c.signByCA([]string{host})
	if err == nil {
		c.certCache.Store(host, cert)
	}

	return cert, err
}

func (c *CA) signByCA(hosts []string) (*tls.Certificate, error) {
	now := time.Now()

	sortedHosts := make([]string, len(hosts))
	copy(sortedHosts, hosts)
	sort.Strings(sortedHosts)

	start := now.Add(-time.Minute)
	end := now.Add(365 * 24 * time.Hour) // 1 year TODO: need configurable?

	h := sha1.New()
	for _, host := range sortedHosts {
		h.Write([]byte(host))
	}
	binary.Write(h, binary.BigEndian, start)
	binary.Write(h, binary.BigEndian, end)
	hash := h.Sum(nil)
	serial := big.Int{}
	serial.SetBytes(hash)

	x509ca := c.Certificate

	template := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       &serial,
		Issuer:             x509ca.Subject,
		Subject: pkix.Name{
			CommonName: hosts[0],
		},
		NotBefore:             start,
		NotAfter:              end,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		DNSNames:              hosts,
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, &template, x509ca, x509ca.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, x509ca.Raw},
		PrivateKey:  c.PrivateKey,
	}
	return cert, nil
}
