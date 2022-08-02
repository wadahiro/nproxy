package nproxy

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func removeProxyHeaders(r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
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

func getHTTPProxyEnv() string {
	return getProxyEnv("http_proxy")
}

func getHTTPSProxyEnv() string {
	return getProxyEnv("https_proxy")
}

func hasProxyEnv() bool {
	return getHTTPProxyEnv() != ""
}

func hasUserInEnvHTTP() bool {
	p := getHTTPProxyEnv()
	u, _ := url.Parse(p)
	if u != nil {
		return u.User != nil
	}
	return false
}

func hasUserInEnvHTTPS() bool {
	p := getHTTPSProxyEnv()
	u, _ := url.Parse(p)
	if u != nil {
		return u.User != nil
	}
	return false
}
