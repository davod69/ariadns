package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"ariadns/internal/config"
)

// certStore serves the current certificate and can hot-swap it (SIGHUP).
type certStore struct {
	cert atomic.Pointer[tls.Certificate]
}

func (s *certStore) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.cert.Load()
	if c == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}
	return c, nil
}

// load reads the certificate named in cfg, or generates a self-signed one.
// It returns a human-readable description for the log.
func (s *certStore) load(cfg config.TLSConfig) (string, error) {
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return "", fmt.Errorf("load TLS certificate: %w", err)
		}
		s.cert.Store(&c)
		return "certificate loaded from " + cfg.CertFile, nil
	}
	if !cfg.SelfSigned {
		return "", fmt.Errorf("no TLS certificate configured")
	}
	c, err := selfSigned(cfg.Hosts)
	if err != nil {
		return "", err
	}
	s.cert.Store(c)
	sum := sha256.Sum256(c.Certificate[0])
	return "self-signed certificate generated (sha256 " + hex.EncodeToString(sum[:]) + ") - testing only", nil
}

func (s *certStore) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.GetCertificate}
}

func selfSigned(hosts []string) (*tls.Certificate, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "AriaDNS self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
