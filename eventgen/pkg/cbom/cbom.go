package cbom

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

type CBOM struct {
	GeneratedAt  string        `json:"generatedAt"`
	Workload     string        `json:"workload,omitempty"`
	Namespace    string        `json:"namespace,omitempty"`
	Certificates []Certificate `json:"certificates"`
	Summary      Summary       `json:"summary"`
}

type Certificate struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serialNumber"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	DaysToExpiry int       `json:"daysToExpiry"`
	IsExpired    bool      `json:"isExpired"`
	IsCA         bool      `json:"isCA"`
	KeyAlgorithm string    `json:"keyAlgorithm"`
	KeySize      int       `json:"keySize"`
	SignatureAlg string    `json:"signatureAlgorithm"`
	SANs         []string  `json:"sans,omitempty"`
	DNSNames     []string  `json:"dnsNames,omitempty"`
	IPAddresses  []string  `json:"ipAddresses,omitempty"`
	Fingerprint  string    `json:"fingerprint"`
	Source       string    `json:"source"`
	Issues       []string  `json:"issues,omitempty"`
}

type Summary struct {
	Total          int `json:"total"`
	Expired        int `json:"expired"`
	ExpiringSoon   int `json:"expiringSoon"`
	WeakAlgorithm  int `json:"weakAlgorithm"`
	ShortKeyLength int `json:"shortKeyLength"`
	SelfSigned     int `json:"selfSigned"`
}

type Scanner struct {
	expirySoonDays int
	minKeySize     int
}

func NewScanner() *Scanner {
	return &Scanner{
		expirySoonDays: 30,
		minKeySize:     2048,
	}
}

func (s *Scanner) SetExpirySoonDays(days int) {
	s.expirySoonDays = days
}

func (s *Scanner) SetMinKeySize(size int) {
	s.minKeySize = size
}

func (s *Scanner) ScanEndpoint(host string, port int) (*CBOM, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	cbom := &CBOM{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Workload:     addr,
		Certificates: []Certificate{},
	}

	return cbom, nil
}

func (s *Scanner) ParsePEM(pemData []byte, source string) (*CBOM, error) {
	cbom := &CBOM{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Certificates: []Certificate{},
	}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				pemData = rest
				continue
			}

			c := s.parseCertificate(cert, source)
			cbom.Certificates = append(cbom.Certificates, c)
		}

		pemData = rest
	}

	cbom.Summary = s.calculateSummary(cbom.Certificates)
	return cbom, nil
}

func (s *Scanner) parseCertificate(cert *x509.Certificate, source string) Certificate {
	now := time.Now()
	daysToExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	c := Certificate{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DaysToExpiry: daysToExpiry,
		IsExpired:    now.After(cert.NotAfter),
		IsCA:         cert.IsCA,
		SignatureAlg: cert.SignatureAlgorithm.String(),
		DNSNames:     cert.DNSNames,
		Fingerprint:  fmt.Sprintf("%x", cert.Raw[:20]),
		Source:       source,
		Issues:       []string{},
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		c.KeyAlgorithm = "RSA"
		if key, ok := cert.PublicKey.(interface{ Size() int }); ok {
			c.KeySize = key.Size() * 8
		}
	case x509.ECDSA:
		c.KeyAlgorithm = "ECDSA"
		if key, ok := cert.PublicKey.(interface{ Params() interface{ BitSize() int } }); ok {
			c.KeySize = key.Params().BitSize()
		}
	case x509.Ed25519:
		c.KeyAlgorithm = "Ed25519"
		c.KeySize = 256
	default:
		c.KeyAlgorithm = "Unknown"
	}

	for _, ip := range cert.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}

	c.SANs = append(c.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		c.SANs = append(c.SANs, ip.String())
	}

	if c.IsExpired {
		c.Issues = append(c.Issues, "EXPIRED")
	} else if daysToExpiry <= s.expirySoonDays {
		c.Issues = append(c.Issues, fmt.Sprintf("EXPIRES_SOON (%d days)", daysToExpiry))
	}

	if c.KeyAlgorithm == "RSA" && c.KeySize < s.minKeySize {
		c.Issues = append(c.Issues, fmt.Sprintf("WEAK_KEY_SIZE (%d bits)", c.KeySize))
	}

	weakAlgs := map[string]bool{
		"MD5WithRSA":    true,
		"SHA1WithRSA":   true,
		"MD2WithRSA":    true,
		"DSAWithSHA1":   true,
		"ECDSAWithSHA1": true,
	}
	if weakAlgs[cert.SignatureAlgorithm.String()] {
		c.Issues = append(c.Issues, "WEAK_SIGNATURE_ALGORITHM")
	}

	if cert.Subject.String() == cert.Issuer.String() && !cert.IsCA {
		c.Issues = append(c.Issues, "SELF_SIGNED")
	}

	return c
}

func (s *Scanner) calculateSummary(certs []Certificate) Summary {
	summary := Summary{Total: len(certs)}

	for _, c := range certs {
		if c.IsExpired {
			summary.Expired++
		} else if c.DaysToExpiry <= s.expirySoonDays {
			summary.ExpiringSoon++
		}

		if c.KeyAlgorithm == "RSA" && c.KeySize < s.minKeySize {
			summary.ShortKeyLength++
		}

		for _, issue := range c.Issues {
			if issue == "WEAK_SIGNATURE_ALGORITHM" {
				summary.WeakAlgorithm++
				break
			}
		}

		for _, issue := range c.Issues {
			if issue == "SELF_SIGNED" {
				summary.SelfSigned++
				break
			}
		}
	}

	return summary
}

func (c *CBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func (c *CBOM) PrintReport() string {
	report := fmt.Sprintf(`Certificate Bill of Materials (CBOM)
Generated: %s
Workload:  %s

SUMMARY
  Total Certificates: %d
  Expired:            %d
  Expiring Soon:      %d
  Weak Algorithm:     %d
  Short Key Length:   %d
  Self-Signed:        %d

CERTIFICATES
`, c.GeneratedAt, c.Workload, c.Summary.Total, c.Summary.Expired,
		c.Summary.ExpiringSoon, c.Summary.WeakAlgorithm,
		c.Summary.ShortKeyLength, c.Summary.SelfSigned)

	for i, cert := range c.Certificates {
		status := "OK"
		if len(cert.Issues) > 0 {
			status = cert.Issues[0]
		}

		report += fmt.Sprintf(`
  [%d] %s
      Subject:    %s
      Issuer:     %s
      Expires:    %s (%d days)
      Algorithm:  %s %d-bit
      Status:     %s
`, i+1, cert.Source, cert.Subject, cert.Issuer,
			cert.NotAfter.Format("2006-01-02"), cert.DaysToExpiry,
			cert.KeyAlgorithm, cert.KeySize, status)
	}

	return report
}

var CommonCertPaths = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/etc/ssl/private",
	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	"/var/run/secrets/kubernetes.io/serviceaccount/token",
	"/etc/kubernetes/pki",
}

var CommonSecretMounts = []string{
	"/etc/tls",
	"/certs",
	"/ssl",
	"/secrets",
}
