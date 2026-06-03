package t1k

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/chaitin/t1k-go/detection"

	"github.com/chaitin/t1k-go/misc"
)

const (
	DEFAULT_POOL_SIZE  = 8
	HEARTBEAT_INTERVAL = 20
)

type Server struct {
	socketFactory func() (net.Conn, error)
	poolCh        chan *conn
	poolSize      int
	count         int
	closeCh       chan struct{}
	logger        *log.Logger
	mu            sync.Mutex
	timeout       time.Duration
}

func (s *Server) newConn() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sock, err := s.socketFactory()
	if err != nil {
		return err
	}
	s.count += 1
	s.poolCh <- makeConn(sock, s)
	return nil
}

func (s *Server) GetConn() (*conn, error) {
	select {
	case c := <-s.poolCh:
		return c, nil
	default:
	}

	if s.count < s.poolSize {
		if err := s.newConn(); err != nil {
			return nil, err
		}
	}

	if s.timeout <= 0 {
		c := <-s.poolCh
		return c, nil
	}
	select {
	case c := <-s.poolCh:
		return c, nil
	case <-time.After(s.timeout):
		return nil, fmt.Errorf("timed out waiting for t1k connection after %s", s.timeout)
	}
}

func (s *Server) PutConn(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.failing {
		s.count -= 1
		c.Close()
	} else {
		s.poolCh <- c
	}
}

func (s *Server) broadcastHeartbeat() {
	l := len(s.poolCh)
	for i := 0; i < l; i++ {
		select {
		case c := <-s.poolCh:
			c.Heartbeat()
			s.PutConn(c)
		default:
			return
		}
	}
}

func (s *Server) runHeartbeatCo() {
	for {
		timer := time.NewTimer(HEARTBEAT_INTERVAL * time.Second)
		select {
		case <-s.closeCh:
			return
		case <-timer.C:
		}
		s.broadcastHeartbeat()
	}
}

func NewFromSocketFactoryWithPoolSizeAndTimeout(socketFactory func() (net.Conn, error), poolSize int, timeout time.Duration) (*Server, error) {
	if poolSize <= 0 {
		poolSize = DEFAULT_POOL_SIZE
	}
	ret := &Server{
		socketFactory: socketFactory,
		poolCh:        make(chan *conn, poolSize),
		poolSize:      poolSize,
		closeCh:       make(chan struct{}),
		logger:        log.New(os.Stdout, "snserver", log.LstdFlags),
		mu:            sync.Mutex{},
		timeout:       timeout,
	}
	for i := 0; i < poolSize; i++ {
		err := ret.newConn()
		if err != nil {
			if ret.count > 0 {
				break
			}
			return nil, err
		}
	}
	go ret.runHeartbeatCo()
	return ret, nil
}

func NewFromSocketFactoryWithPoolSize(socketFactory func() (net.Conn, error), poolSize int) (*Server, error) {
	return NewFromSocketFactoryWithPoolSizeAndTimeout(socketFactory, poolSize, 0)
}

func NewFromSocketFactory(socketFactory func() (net.Conn, error)) (*Server, error) {
	return NewFromSocketFactoryWithPoolSize(socketFactory, DEFAULT_POOL_SIZE)
}

func NewWithPoolSizeAndTimeout(addr string, poolSize int, timeout time.Duration) (*Server, error) {
	return NewFromSocketFactoryWithPoolSizeAndTimeout(func() (net.Conn, error) {
		if timeout > 0 {
			return net.DialTimeout("tcp", addr, timeout)
		}
		return net.Dial("tcp", addr)
	}, poolSize, timeout)
}

func NewWithPoolSize(addr string, poolSize int) (*Server, error) {
	return NewWithPoolSizeAndTimeout(addr, poolSize, 0)
}

func New(addr string) (*Server, error) {
	return NewWithPoolSize(addr, DEFAULT_POOL_SIZE)
}

func (s *Server) DetectRequestInCtx(dc *detection.DetectionContext) (*detection.Result, error) {
	c, err := s.GetConn()
	if err != nil {
		return nil, err
	}
	defer s.PutConn(c)
	return c.DetectRequestInCtx(dc)
}

func (s *Server) DetectResponseInCtx(dc *detection.DetectionContext) (*detection.Result, error) {
	c, err := s.GetConn()
	if err != nil {
		return nil, misc.ErrorWrap(err, "")
	}
	defer s.PutConn(c)
	return c.DetectResponseInCtx(dc)
}

func (s *Server) Detect(dc *detection.DetectionContext) (*detection.Result, *detection.Result, error) {
	c, err := s.GetConn()
	if err != nil {
		return nil, nil, misc.ErrorWrap(err, "")
	}

	reqResult, rspResult, err := c.Detect(dc)
	if err == nil {
		s.PutConn(c)
	}
	return reqResult, rspResult, err
}

func (s *Server) DetectHttpRequest(req *http.Request) (*detection.Result, error) {
	c, err := s.GetConn()
	if err != nil {
		return nil, err
	}
	defer s.PutConn(c)
	return c.DetectHttpRequest(req)
}

func (s *Server) DetectRequest(req detection.Request) (*detection.Result, error) {
	c, err := s.GetConn()
	if err != nil {
		return nil, err
	}
	defer s.PutConn(c)
	return c.DetectRequest(req)
}

// blocks until all pending detection is completed
func (s *Server) Close() {
	close(s.closeCh)
	for i := 0; i < s.count; i++ {
		c, err := s.GetConn()
		if err != nil {
			return
		}
		c.Close()
	}
}
