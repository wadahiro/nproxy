package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	r "math/rand"
	"os"
	"time"

	"path/filepath"

	"github.com/comail/colog"
	proxy "github.com/wadahiro/nproxy"
)

var (
	version  string
	revision string

	fs = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	bindAddr = fs.String("b", ":3128", "Bind address and port")

	caCertPEMFile       = fs.String("ca-cert", "", "CA cert file (PEM)")
	caPrivateKeyPEMFile = fs.String("ca-key", "", "CA private key file (PEM)")

	pacURL           = fs.String("pac", "", "PAC URL")
	overridePacProxy = fs.String("override-pac-proxy", "", "Set upstream proxy server:port to override proxy in PAC file")

	loglevel = fs.String(
		"log-level",
		"info",
		"Log level, one of: debug, info, warn, error, panic",
	)

	enableDump                = fs.Bool("enable-dump", false, "Enable request/response dump")
	insecure                  = fs.Bool("insecure", false, "Skip certificate verification when connecting to upstream (Don't use!)")
	disableReplaceInvalidCert = fs.Bool("disable-replace-invalid-cert", false, "Skip replacing invalid server certificate when detecting invalid")
	alwaysMITMHTTPS           = fs.Bool("always-mitm-https", false, "Always mitm when using https")

	genCA = fs.Bool("gen-ca", false, "Generate own CA certificate and private key")
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "nproxy %s (rev: %s)\n", version, revision)
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// seed the global random number generator, used in secureoperator
	r.Seed(time.Now().UTC().UnixNano())

	// setup logger
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LInfo)
	level, err := colog.ParseLevel(*loglevel)
	if err != nil {
		log.Fatalf("alert: Invalid log level: %s", err.Error())
	}
	colog.SetMinLevel(level)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds,
	})
	colog.ParseFields(true)
	colog.Register()

	if *genCA {
		generateCA()
		return
	}

	f := proxy.NewServer(&proxy.ServerConfig{
		BindAddr:                  *bindAddr,
		CACertFilePath:            *caCertPEMFile,
		CAKeyFilePath:             *caPrivateKeyPEMFile,
		PACURL:                    *pacURL,
		OverridePACProxy:          *overridePacProxy,
		EnableDump:                *enableDump,
		Insecure:                  *insecure,
		DisableReplaceInvalidCert: *disableReplaceInvalidCert,
		AlwaysMITMHTTPS:           *alwaysMITMHTTPS,
	})

	log.Printf("info: Starting NPROXY: %s", *bindAddr)

	if err := f.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}
}

func generateCA() {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("alert: Failed to genarate private keys, err: %v", err)
	}

	keyToFile("ca.key", k)

	serial, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
	if err != nil {
		log.Fatalf("alert: Failed to genarate serial number, err: %v", err)
	}

	now := time.Now()

	rootTemplate := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			CommonName: "NPROXY Root",
		},
		NotBefore:             now.Add(-10 * time.Minute).UTC(),
		NotAfter:              now.Add(365 * 24 * time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &k.PublicKey, k)
	if err != nil {
		log.Fatalf("alert: Failed to create certificate. err: %v", err)
	}
	certToFile("ca.crt", derBytes)
}

func keyToFile(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("alert: Failed to create key file. err: %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		log.Fatalf("alert: Failed to write key PEM. err: %v", err)
	}
}

func certToFile(filename string, derBytes []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("alert: Failed to create cert file. err: %v", err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("alert: Failed to write cert PEM. err: %v", err)
	}
}
