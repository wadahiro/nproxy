package nproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/proxy"
)

// VerifyCertificate verify the peer certificate with Apple's requirements for trusted certificates.
// See https://support.apple.com/en-in/HT210176
func (s *Server) VerifyCertificate(r *http.Request) error {
	conn, err := connect(r, s.proxy)
	if err != nil {
		// Don't use mitm proxy
		log.Printf("warn: Failed to connect for certificate verification. Skipped it. reason: %v", err)
		return nil
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		// Don't use mitm proxy
		// return fmt.Errorf("Failed to do handshake. %w", err)
		return nil
	}

	target := r.URL
	c := conn.ConnectionState().PeerCertificates[0]

	if err := verifyDNSNames(c, target.Hostname()); err != nil {
		return fmt.Errorf("Failed to verify DNSName. %w", err)
	}

	if err := verifyValidityPeriod(c); err != nil {
		return fmt.Errorf("Failed to verify validity period. %w", err)
	}

	if err := verifyAlg(c); err != nil {
		return fmt.Errorf("Failed to verify algorithm. %w", err)
	}

	if err := verifyRSAKeySize(c); err != nil {
		return fmt.Errorf("Failed to verify RSA key size. %w", err)
	}

	return nil
}

func connect(r *http.Request, p Proxy) (*tls.Conn, error) {
	target := r.URL

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         target.Hostname(),
		// VerifyPeerCertificate: verify,
	}

	u, err := p.Find(r)
	if err != nil {
		log.Printf("error: Find upstream proxy error: %s, %v", target.Host, err)
		return nil, err
	}

	if u == nil {
		// DIRECT
		return tls.Dial("tcp", target.Host, tlsConfig)
	}

	dialer := &net.Dialer{
		KeepAlive: 1 * time.Minute,
		DualStack: true,
	}

	pdialer, err := proxy.FromURL(u, dialer)
	if err != nil {
		return nil, fmt.Errorf("error: Failed to create Dialer from proxy URL. url: %s://%s, err %w", u.Scheme, u.Host, err)
	}

	dest, err := pdialer.Dial("tcp", target.Host)
	if err != nil {
		return nil, fmt.Errorf("error: Failed to connect. addr: %s, err: %w", target.Host, err)
	}

	// verify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// 	for j, certs := range verifiedChains {
	// 		for i, c := range certs {
	// 			log.Printf("%d %d %s", j, i, c.Subject)
	// 			if i == 0 {
	// 				if err := verifyDNSNames(c, target.Hostname()); err != nil {
	// 					return err
	// 				}

	// 				if err := verifyValidityPeriod(c); err != nil {
	// 					return err
	// 				}
	// 			}

	// 			if err := verifyAlg(c); err != nil {
	// 				return err
	// 			}
	// 		}
	// 	}

	// 	return nil
	// }

	tlsConn := tls.Client(dest, tlsConfig)

	return tlsConn, nil
}

func verifyDNSNames(c *x509.Certificate, host string) error {
	if len(c.DNSNames) == 0 {
		return fmt.Errorf("The certificate must present the DNS name of the server in the Subject Alternative Name extension. host: %s", host)
	}

	lowered := toLowerCaseASCII(host)

	for _, match := range c.DNSNames {
		if matchHostnames(toLowerCaseASCII(match), lowered) {
			log.Printf("debug: DNSName is OK. host: %s", host)
			return nil
		}
	}

	return fmt.Errorf("The certificate must present the DNS name of the server in the Subject Alternative Name extension. host: %s, DNSNames: %v", host, c.DNSNames)
}

func verifyValidityPeriod(c *x509.Certificate) error {
	start := time.Date(2019, time.December, 1, 7, 0, 0, 0, time.UTC)
	if d := c.NotBefore.Sub(start); d < 0 {
		log.Printf("debug: The validity period is OK since it was issued before 2019-07-01.")
		return nil
	}

	duration := c.NotAfter.Sub(c.NotBefore)

	hours := int(duration.Hours())
	days := hours / 24

	if days > 825 {
		return fmt.Errorf("The certificate must have validity period of 825 days or fewer. NotBefore: %v, NotAfter: %v, duration: %d days", c.NotBefore, c.NotAfter, days)
	}

	return nil
}

func verifyAlg(c *x509.Certificate) error {
	log.Printf("debug: Signature Alg: %d", c.SignatureAlgorithm)

	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm ||
		c.SignatureAlgorithm == x509.MD2WithRSA ||
		c.SignatureAlgorithm == x509.MD5WithRSA ||
		c.SignatureAlgorithm == x509.SHA1WithRSA ||
		c.SignatureAlgorithm == x509.ECDSAWithSHA1 {

		return fmt.Errorf("The certificate must use a hash algorithm from the SHA-2 family in the signature algorithm. alg: %d", c.SignatureAlgorithm)
	}

	return nil
}

func verifyRSAKeySize(c *x509.Certificate) error {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		size := pub.N.BitLen()
		log.Printf("debug: RSA key size: %d", size)
		if size < 2048 {
			return fmt.Errorf("The certificate must use key sizes greater than or equal to 2048 bits. size: %d", pub.Size())
		}
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////
// Copy from crypto/x509/verify.go
///////////////////////////////////////////////////////////////////////////////////////

// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// Copy from crypto/x509/verify.go
func matchHostnames(pattern, host string) bool {
	host = strings.TrimSuffix(host, ".")
	pattern = strings.TrimSuffix(pattern, ".")

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}
