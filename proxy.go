package nproxy

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/darren/gpac"
)

var mu sync.Mutex

// Proxy has a role to find an upstream proxy.
type Proxy interface {
	Find(req *http.Request) (*url.URL, error)
}

// NewProxy returns new Proxy. If pacURL isn't empty, returns PACProxy.
func NewProxy(config *ServerConfig) Proxy {
	pacURL := config.PACURL

	notify := func() {
		// Notify using user info for proxy authorization
		if hasUserInEnvHTTP() {
			log.Printf("info: Detected userInfo for HTTP proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.")
		}
		if hasUserInEnvHTTPS() {
			log.Printf("info: Detected userInfo for HTTPS proxy in environment variables. The userInfo is used as Proxy Authorization for the upstream proxy.")
		}
	}

	if pacURL == "" {
		if hasProxyEnv() {
			log.Printf("info: No pac URL. The proxy uses standard environment variables for upstream proxy.")
			notify()
		} else {
			log.Printf("info: No pac URL and environment variable. The proxy doesn't use upstream proxy.")
		}

		return &EnvProxy{}
	}

	notify()

	// Replace default proxy for fetching pac file
	defaultProxy := http.DefaultTransport.(*http.Transport).Proxy
	http.DefaultTransport.(*http.Transport).Proxy = func(req *http.Request) (*url.URL, error) {
		return nil, nil
	}
	defer func() { http.DefaultTransport.(*http.Transport).Proxy = defaultProxy }()

	pac, err := gpac.From(pacURL)
	if err != nil {
		log.Printf("warn: Failed to load pac file. Try to reload on the fly... pac URL: %s, err: %v", pacURL, err)
	}

	if config.OverridePACProxy == "" {
		log.Printf("info: Got pac file from %s", pacURL)
	} else {
		log.Printf("info: Got pac file from %s but override the proxy with specified proxy server", pacURL)
	}

	return &PACProxy{
		URL:              pacURL,
		OverridePACProxy: config.OverridePACProxy,
		pac:              pac,
		noProxyChecker:   &EnvProxy{},
	}
}

// EnvProxy is a Proxy implmentation using standard environment variables.
type EnvProxy struct {
}

// Find proxy URL from starndard environment variables.
func (p *EnvProxy) Find(req *http.Request) (*url.URL, error) {
	var schema string
	if req.Method == http.MethodConnect {
		schema = "https"
	} else {
		schema = req.URL.Scheme
	}

	u, err := url.Parse(schema + "://" + req.Host)
	if err != nil {
		log.Printf("error: Invalid request URL for EnvProxy. err: %v", err)
		return nil, err
	}

	r := &http.Request{
		URL: u,
	}

	log.Printf("debug: Find proxy from environment for: %s", r.URL.String())

	return http.ProxyFromEnvironment(r)
}

// PACProxy is a Proxy implementation using pac file.
type PACProxy struct {
	URL              string
	OverridePACProxy string
	pac              *gpac.Parser
	noProxyChecker   Proxy
}

// Find proxy URL from request using pac file.
func (p *PACProxy) Find(req *http.Request) (*url.URL, error) {
	var schema string
	var envp string

	if req.Method == http.MethodConnect {
		schema = "https"
		envp = getHTTPSProxyEnv()
	} else {
		schema = req.URL.Scheme
		envp = getHTTPProxyEnv()
	}

	var user *url.Userinfo

	if envp != "" {
		u, err := url.Parse(envp)
		if err != nil {
			log.Printf("warn: Invalid proxy URL in environment variables. Ignored it. err: %v", err)
		}
		user = u.User
	}

	absURL := fmt.Sprintf("%s://%s/%s", schema, req.URL.Hostname(), req.URL.RawPath)

	log.Printf("debug: Find proxy from pac. URL: %s", absURL)

	if p.pac == nil {
		if err := p.Reload(); err != nil {
			return nil, err
		}
	}

	// First, check no_proxy from environment variable
	urls, err := p.noProxyChecker.Find(req)
	if err != nil {
		log.Printf("error: Failed to check no_proxy. %v", err)
		return nil, err
	}
	if urls == nil {
		// no_proxy
		log.Printf("debug: Don't use upstream proxy because it's detected by no_proxy")
		return nil, nil
	}

	// Find by PAC
	proxies, err := p.pac.FindProxy(absURL)
	if err != nil {
		log.Printf("error: Failed to find proxy from the pac. %v", err)
		return nil, err
	}

	var u *url.URL

	for _, proxy := range proxies {
		if proxy.IsDirect() {
			log.Printf("debug: No proxy from the pac.")
			return nil, nil
		}
		var proxyAddr string
		if p.OverridePACProxy != "" {
			log.Printf("debug: Override pac proxy.")
			proxyAddr = p.OverridePACProxy
		} else {
			proxyAddr = proxy.Address
		}
		if proxy.IsSOCKS() {
			u, err = url.Parse(fmt.Sprintf("sock5://%s", proxyAddr))
			break
		} else {
			u, err = url.Parse(fmt.Sprintf("http://%s", proxyAddr))
			break
		}
	}

	if err != nil {
		log.Printf("error: Failed to find proxy from the pac. %v", err)
		return nil, err
	}

	if u == nil {
		log.Printf("debug: Not found proxy from the pac.")
		return nil, nil
	}

	log.Printf("debug: Found proxy from pac: %s", u.String())

	if user != nil {
		log.Printf("debug: Detected proxy user in environment variables. Use the userInfo.")
		u.User = user
	}

	return u, nil
}

// Reload gets latest pac file from the URL.
func (p *PACProxy) Reload() error {
	mu.Lock()
	defer mu.Unlock()

	pac, err := gpac.From(p.URL)
	if err != nil {
		return fmt.Errorf("Failed to load pac file. %w", err)
	}

	p.pac = pac

	return nil
}
