package nproxy

import (
	"io"
	"log"

	"net/http"
)

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.dumpRequest(r)

	removeProxyHeaders(r)

	// transport request to target host
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		log.Printf("error: Faild to read response. host: %v, err: %v", r.URL.Host, err.Error())
		if resp == nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	s.dumpResponse(resp)

	s.writeResponse(w, resp)
}

func (s *Server) writeResponse(w http.ResponseWriter, resp *http.Response) {
	// copy headers
	dest := w.Header()
	for k, vs := range resp.Header {
		for _, v := range vs {
			dest.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	_, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("warn: Can't read response body %v", err)
	}

	if err := resp.Body.Close(); err != nil {
		log.Printf("warn: Can't close response body %v", err)
	}
}
