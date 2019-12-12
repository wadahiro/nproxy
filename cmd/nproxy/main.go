package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"path/filepath"

	"github.com/comail/colog"
	proxy "github.com/wadahiro/nproxy"
)

var (
	fs = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	bindAddr = fs.String("b", ":3128", "Bind address and port")

	caCertPEMFile       = fs.String("ca-cert", "", "CA cert file (PEM)")
	caPrivateKeyPEMFile = fs.String("ca-key", "", "CA private key file (PEM)")

	pacURL = fs.String("pac", "", "PAC URL")

	loglevel = fs.String(
		"log-level",
		"info",
		"Log level, one of: debug, info, warn, error, panic",
	)

	enableDump = fs.Bool("enable-dump", false, "Enable request/response dump")
	insecure   = fs.Bool("insecure", false, "Skip certificate verification when connecting to upstream")
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "nproxy.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

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

	f := proxy.NewServer(&proxy.ServerConfig{
		BindAddr:       *bindAddr,
		CACertFilePath: *caCertPEMFile,
		CAKeyFilePath:  *caPrivateKeyPEMFile,
		PACURL:         *pacURL,
		EnableDump:     *enableDump,
		Insecure:       *insecure,
	})

	log.Printf("info: Starting NPROXY: %s", *bindAddr)

	if err := f.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}
}
