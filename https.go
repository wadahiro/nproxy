package nproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"crypto/tls"
)

func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("debug: Start handleHTTPS. method: %s, URL: %s", r.Method, r.URL.String())

	u, _ := s.proxy.Find(r)

	// Don't check the certificate if no upstream proxy
	if u == nil {
		directTransfer(w, r)
	} else {
		if s.ca != nil {
			// TODO: Cache timeout
			useMitm, ok := s.tlsCache.Load(r.URL.Host)
			if !ok {
				if err := s.VerifyCertificate(r); err != nil {
					log.Printf("info: Untrusted certificate. Let's hack! reason: %v", err)

					useMitm = true
					s.tlsCache.Store(r.URL.Host, true)
				} else {
					log.Printf("debug: Trusted certificate.")

					s.tlsCache.Store(r.URL.Host, false)
				}
			}
			if useMitm {
				s.mitmRequest(w, r)
			}
		}
		proxyTransfer(w, r, u)
	}
}

func directTransfer(w http.ResponseWriter, r *http.Request) {
	dest, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("error: Failed to connect. host: %s, err: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	conn := hijackConnect(w)
	conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	log.Printf("debug: Relaying tcp packets. method: %s, URL: %s", r.Method, r.URL.String())

	go transfer(dest, conn)
	go transfer(conn, dest)
}

func proxyTransfer(w http.ResponseWriter, r *http.Request, proxyURL *url.URL) {
	dest, err := net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
	if err != nil {
		log.Printf("error: Failed to connect proxy. proxyHost: %s, err: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	conn := hijackConnect(w)

	proxyAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))

	r.Header.Set("Proxy-Authorization", proxyAuthorization)

	r.Write(dest)

	log.Printf("debug: Relaying tcp packets. method: %s, URL: %s", r.Method, r.URL.String())

	go transfer(dest, conn)
	go transfer(conn, dest)
}

func transfer(dest io.WriteCloser, source io.ReadCloser) {
	defer dest.Close()
	defer source.Close()
	io.Copy(dest, source)
}

func (s *Server) mitmRequest(w http.ResponseWriter, r *http.Request) {
	conn := hijackConnect(w)
	conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	// launch goroutine to transporting request with mitm sniffing
	go s.transportHTTPSRequest(w, r, conn)
}

func hijackConnect(w http.ResponseWriter) net.Conn {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatalf("alert: httpserver does not support hijacking")
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		log.Fatalf("alert: Cannot hijack connection " + err.Error())
	}

	return conn
}

func (s *Server) transportHTTPSRequest(w http.ResponseWriter, r *http.Request, conn net.Conn) {
	log.Printf("debug: transportHTTPSRequest : %s %s", r.Method, r.URL.String())

	host := r.Host
	tlsConfig, err := s.generateTLSConfig(host)
	if err != nil {
		if _, err := conn.Write([]byte("HTTP/1.0 500 Internal Server Error\r\n\r\n")); err != nil {
			log.Printf("error: Failed to write response : %v", err)
		}
		conn.Close()
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("warn: Cannot handshake client %v %v", r.Host, err)
		return
	}
	defer tlsConn.Close()

	log.Printf("debug: transportHTTPSRequest : established tls connection")

	tlsIn := bufio.NewReader(tlsConn)
	for !isEOF(tlsIn) {
		req, err := http.ReadRequest(tlsIn)
		if err != nil {
			if err == io.EOF {
				log.Printf("error: EOF detected when read request from client: %v %v", r.Host, err)
			} else {
				log.Printf("error: Cannot read request from client: %v %v", r.Host, err)
			}
			return
		}

		log.Printf("debug: transportHTTPSRequest : read request : %s %s", req.Method, req.URL.String())

		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = req.URL.String()
		req.RemoteAddr = r.RemoteAddr

		s.dumpRequest(req)

		removeProxyHeaders(req)

		// transport request to target host
		resp, err := s.transport.RoundTrip(req)
		if err != nil {
			log.Printf("error: Failed to read response %v %v", r.URL.Host, err.Error())
			if resp == nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}

		log.Printf("debug: transportHTTPSRequest : transport request: %s", resp.Status)

		s.dumpResponse(resp)

		// copy response to client
		resp.Write(tlsConn)
	}

	log.Printf("debug: transportHTTPSRequest : finished ")
}

func isEOF(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	if err == io.EOF {
		return true
	}
	return false
}

func (s *Server) generateTLSConfig(host string) (*tls.Config, error) {
	config := tls.Config{InsecureSkipVerify: s.Insecure}

	host, _ = splitHostPort(host)

	log.Printf("warn: generate tls config for : %s", host)

	cert, err := s.ca.FindOrCreateCert(host)
	if err != nil {
		log.Printf("warn: failed to find cert : %s : %v", host, err)
		return nil, err
	}

	config.Certificates = append(config.Certificates, *cert)
	return &config, nil
}
