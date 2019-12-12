package nproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/proxy"
)

// Verify the peer certificate with Apple's requirements for trusted certificates.
// See https://support.apple.com/en-in/HT210176
func VerifyCertificate(target *url.URL) error {
	conn, err := connect(target)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	c := conn.ConnectionState().PeerCertificates[0]

	if err := verifyDNSNames(c, target.Hostname()); err != nil {
		return err
	}

	if err := verifyValidityPeriod(c); err != nil {
		return err
	}

	if err := verifyAlg(c); err != nil {
		return err
	}

	if err := verifyRSAKeySize(c); err != nil {
		return err
	}

	return nil
}

func connect(target *url.URL) (*tls.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 1 * time.Minute,
		DualStack: true,
	}

	u, err := url.Parse(getProxyEnv("https_proxy"))
	if err != nil {
		log.Printf("error: Failed to parse proxy URL. url: %s://%s, err: %v", u.Scheme, u.Host, err)
		return nil, err
	}

	pdialer, err := proxy.FromURL(u, dialer)
	if err != nil {
		log.Printf("error: Failed to create Dialer from proxy URL. url: %s://%s, err %v", u.Scheme, u.Host, err)
		return nil, err
	}

	dest, err := pdialer.Dial("tcp", target.Host)
	if err != nil {
		log.Printf("error: Failed to connect. addr: %s, err: %v", target.Host, err)
		return nil, err
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

	tlsConn := tls.Client(dest, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         target.Hostname(),
		// VerifyPeerCertificate: verify,
	})

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
	duration := c.NotAfter.Sub(c.NotBefore)

	hours := int(duration.Hours())
	days := hours / 24

	if days > 825 {
		return fmt.Errorf("The certificate must have validity period of 825 days or fewer")
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
