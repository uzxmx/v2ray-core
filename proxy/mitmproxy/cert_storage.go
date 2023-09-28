package mitmproxy

import (
	"crypto/tls"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

type CertStorage interface {
	// Get gets the certificate from the storage
	Get(hostname string) (*tls.Certificate, bool)
	// Add adds the certificate to the storage
	Add(hostname string, cert *tls.Certificate)
}

// MapCertStorage is a simple map-based CertStorage implementation
type MapCertStorage struct {
	cache map[string]*tls.Certificate
	mu    sync.RWMutex
}

func NewMapCertStorage() *MapCertStorage {
	return &MapCertStorage{
		cache: make(map[string]*tls.Certificate),
	}
}

// Get gets the certificate from the storage
func (s *MapCertStorage) Get(hostname string) (*tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.cache[hostname]

	return v, ok
}

// Add adds the certificate to the storage
func (s *MapCertStorage) Add(hostname string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[hostname] = cert
}

// LRUCertStorage is lru-based CertStorage implementation
type LRUCertStorage struct {
	cache *lru.Cache
}

func NewLRUStorage(cacheSize int) (*LRUCertStorage, error) {
	lru, err := lru.New(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("could not create lru cache: %s", err)
	}

	return &LRUCertStorage{
		cache: lru,
	}, nil
}

// Get gets the certificate from the storage
func (s *LRUCertStorage) Get(hostname string) (*tls.Certificate, bool) {
	cert, ok := s.cache.Get(hostname)
	if ok {
		return cert.(*tls.Certificate), ok
	}

	return nil, false
}

// Add adds the certificate to the storage
func (s *LRUCertStorage) Add(hostname string, cert *tls.Certificate) {
	s.cache.Add(hostname, cert)
}
