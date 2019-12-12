package nproxy

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")
}

func splitHostPort(s string) (string, string) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		log.Printf("warn: Failed to split host and port : %s : %v", s, err)
		port = ""
	}
	return host, port
}

func getProxyEnv(key string) string {
	env := os.Getenv(key)
	if env == "" {
		env = os.Getenv(strings.ToUpper(key))
	}
	return env
}
