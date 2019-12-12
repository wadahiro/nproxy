package nproxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

type Server struct {
	ServerConfig
	transport *http.Transport
	ca        *CA
	proxy     Proxy
}

type ServerConfig struct {
	BindAddr       string
	CACertFilePath string
	CAKeyFilePath  string
	PACURL         string
	EnableDump     bool
	Insecure       bool
}

func NewServer(config *ServerConfig) *Server {
	p := NewProxy(config.PACURL)

	s := &Server{
		ServerConfig: *config,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
			Proxy: p.Find, // For HTTP
		},
		ca:    NewCA(config.CACertFilePath, config.CAKeyFilePath),
		proxy: p,
	}

	return s
}

func (s *Server) Start() error {
	if s.BindAddr == "" {
		log.Fatalf("alert: Bind address is empty.")
	}
	return http.ListenAndServe(s.BindAddr, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("debug: ServeHTTP")

	if r.Method == http.MethodConnect {
		s.handleHTTPS(w, r)
		return
	}

	s.handleHTTP(w, r)
}

func logging(level, s string, v ...interface{}) {
	msg := fmt.Sprintf(s, v...)
	log.Printf("[%s] %s\n", level, msg)
}

func (s *Server) dumpRequest(req *http.Request) {
	if s.EnableDump {
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("-> Request : %s %s\n", req.Method, req.URL)
		dump, _ := httputil.DumpRequestOut(req, true)
		fmt.Println(string(dump))
		fmt.Println("---------------------------------------------------------------------")
	}
}

func (s *Server) dumpResponse(resp *http.Response) {
	if s.EnableDump {
		dumpResp, _ := httputil.DumpResponse(resp, true)
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("<- Response: %s %s\n", resp.Request.Method, resp.Request.URL)
		fmt.Println(string(dumpResp))
		fmt.Println("---------------------------------------------------------------------")
	}
}
