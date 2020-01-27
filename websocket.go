package nproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"strings"
)

// Based on https://github.com/elazarl/goproxy/blob/master/websocket.go

// Copyright (c) 2012 Elazar Leibovich. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Elazar Leibovich. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

func (s *Server) isWebSocketRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	return false
}

func (s *Server) serveWebsocketTLS(w http.ResponseWriter, req *http.Request, tlsConfig *tls.Config, clientConn *tls.Conn) {
	// targetURL := url.URL{Scheme: "wss", Host: req.URL.Host, Path: req.URL.Path}

	// Connect to upstream
	targetConn, err := connect(req, s.proxy)
	// targetConn, err := tls.Dial("tcp", targetURL.Host, tlsConfig)
	if err != nil {
		log.Printf("error: Error dialing target site: %v", err)
		return
	}
	defer targetConn.Close()

	// Perform handshake
	if err := s.websocketHandshake(req, targetConn, clientConn); err != nil {
		log.Printf("error: Websocket handshake error: %v", err)
		return
	}

	// Proxy wss connection
	s.proxyWebsocket(targetConn, clientConn)
}

func (s *Server) websocketHandshake(req *http.Request, targetSiteConn io.ReadWriter, clientConn io.ReadWriter) error {
	// write handshake request to target
	err := req.Write(targetSiteConn)
	if err != nil {
		log.Printf("error: Error writing upgrade request: %v", err)
		return err
	}

	targetTLSReader := bufio.NewReader(targetSiteConn)

	// Read handshake response from target
	resp, err := http.ReadResponse(targetTLSReader, req)
	if err != nil {
		log.Printf("error: Error reading handhsake response: %v", err)
		return err
	}

	if !strings.EqualFold(resp.Header.Get("Connection"), "upgrade") {
		resp.Header.Add("Connection", "upgrade")
	}

	// Proxy handshake back to client
	err = resp.Write(clientConn)
	if err != nil {
		log.Printf("error: Error writing handshake response: %v", err)
		return err
	}
	return nil
}

func (s *Server) proxyWebsocket(dest io.ReadWriter, source io.ReadWriter) {
	errChan := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Printf("error: Websocket error: %v", err)
		}
		errChan <- err
	}

	// Start proxying websocket data
	go cp(dest, source)
	go cp(source, dest)
	<-errChan
}
