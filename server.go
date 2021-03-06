package nproxy

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

type Server struct {
	ServerConfig
	transport   *http.Transport
	ca          *CA
	proxy       Proxy
	tlsCache    *tlsCache
	caCertCache []byte
}

type ServerConfig struct {
	BindAddr                  string
	CACertFilePath            string
	CAKeyFilePath             string
	PACURL                    string
	OverridePACProxy          string
	EnableDump                bool
	DisableReplaceInvalidCert bool
	AlwaysMITMHTTPS           bool
	Insecure                  bool
}

func NewServer(config *ServerConfig) *Server {
	p := NewProxy(config)

	var caCertCache []byte
	if config.CACertFilePath != "" {
		b, err := ioutil.ReadFile(config.CACertFilePath)
		if err != nil {
			log.Fatalf("alert: Failed to load ca-cert file. err: %v", err)
			return nil
		}
		caCertCache = b
	}

	s := &Server{
		ServerConfig: *config,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
			},
			Proxy: p.Find, // For HTTP and HTTPS with mitm
		},
		ca:          NewCA(config.CACertFilePath, config.CAKeyFilePath),
		proxy:       p,
		tlsCache:    NewTLSCache(),
		caCertCache: caCertCache,
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

	if r.URL.Path == "/pac" {
		s.handlePAC(w, r)
		return
	}

	if r.URL.Path == "/cert" {
		s.handleCert(w, r)
		return
	}

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

func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	addr := strings.Split(s.BindAddr, ":")
	server := addr[0]
	port := addr[1]
	if server == "" {
		server = "127.0.0.1"
	}

	var scripts = fmt.Sprintf(`
	function FindProxyForURL(url, host) {
	  if (isPlainHostName(host)) {
		  return DIRECT;
	  }
	  return "PROXY %s:%s;";
	}
  `, server, port)
	fmt.Fprintf(w, scripts)
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if len(s.caCertCache) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Write(s.caCertCache)
}

type tlsCache struct {
	sm sync.Map
}

func (m *tlsCache) Load(host string) (bool, bool) {
	val, ok := m.sm.Load(host)
	if !ok {
		return false, false
	}
	return val.(bool), true
}

func (m *tlsCache) Store(host string, useMitm bool) {
	m.sm.Store(host, useMitm)
}

func NewTLSCache() *tlsCache {
	return &tlsCache{}
}
