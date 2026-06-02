package traefik_safeline

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	t1k "github.com/chaitin/t1k-go"
	"github.com/chaitin/t1k-go/detection"
)

// Package example a example plugin.

// Config the plugin configuration.
type Config struct {
	// Addr is the address for the detector
	Addr     string `yaml:"addr"`
	PoolSize int    `yaml:"pool_size"`
	Timeout  string `yaml:"timeout"`
	FailOpen bool   `yaml:"fail_open"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Addr:     "",
		PoolSize: 100,
		Timeout:  "2s",
		FailOpen: true,
	}
}

// Safeline a plugin.
type Safeline struct {
	next    http.Handler
	server  *t1k.Server
	name    string
	config  *Config
	logger  *log.Logger
	mu      sync.Mutex
	timeout time.Duration
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logger := log.New(os.Stdout, "safeline", log.LstdFlags)
	logger.Printf("config: %+v", config)
	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid safeline timeout %q: %w", config.Timeout, err)
	}
	return &Safeline{
		next:    next,
		name:    name,
		config:  config,
		logger:  logger,
		timeout: timeout,
	}, nil
}

func (s *Safeline) initServer() error {
	if s.server != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server == nil {
		server, err := t1k.NewWithPoolSizeAndTimeout(s.config.Addr, s.config.PoolSize, s.timeout)
		if err != nil {
			return err
		}
		s.server = server
	}
	return nil
}

func (s *Safeline) detect(req *http.Request) (result *detection.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in detection: %v", r)
		}
	}()
	return s.server.DetectHttpRequest(req)
}

func (s *Safeline) failThrough(rw http.ResponseWriter, req *http.Request, err error) {
	s.logger.Printf("error in detection: \n%+v\n", err)
	if s.config.FailOpen {
		s.next.ServeHTTP(rw, req)
		return
	}
	http.Error(rw, "SafeLine detector unavailable", http.StatusServiceUnavailable)
}

func (s *Safeline) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := s.initServer(); err != nil {
		s.logger.Printf("error in initServer: %s", err)
		if s.config.FailOpen {
			s.next.ServeHTTP(rw, req)
			return
		}
		http.Error(rw, "SafeLine detector unavailable", http.StatusServiceUnavailable)
		return
	}
	rw.Header().Set("X-Chaitin-waf", "safeline")
	result, err := s.detect(req)
	if err != nil {
		s.failThrough(rw, req, err)
		return
	}
	if result.Blocked() {
		rw.WriteHeader(result.StatusCode())
		msg := fmt.Sprintf(`{"code": %d, "success":false, "message": "blocked by Chaitin SafeLine Web Application Firewall", "event_id": "%s"}`,
			result.StatusCode(),
			result.EventID(),
		)
		_, _ = rw.Write([]byte(msg))
		return
	}
	s.next.ServeHTTP(rw, req)
	//rw.WriteHeader(http.StatusForbidden)
	//_, _ = rw.Write([]byte("Inject by safeline\n"))
}
