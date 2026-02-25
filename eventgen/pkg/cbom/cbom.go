package cbom

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

type CBOM struct {
	GeneratedAt  string        `json:"generatedAt"`
	Container    string        `json:"container,omitempty"`
	Image        string        `json:"image,omitempty"`
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
	Path         string    `json:"path"`
	Issues       []string  `json:"issues,omitempty"`
}

type Summary struct {
	Total          int      `json:"total"`
	Expired        int      `json:"expired"`
	ExpiringSoon   int      `json:"expiringSoon"`
	WeakAlgorithm  int      `json:"weakAlgorithm"`
	ShortKeyLength int      `json:"shortKeyLength"`
	SelfSigned     int      `json:"selfSigned"`
	PathsScanned   []string `json:"pathsScanned"`
}

type Scanner struct {
	expirySoonDays int
	minKeySize     int
	runtime        string
}

func NewScanner() *Scanner {
	return &Scanner{
		expirySoonDays: 30,
		minKeySize:     2048,
		runtime:        detectRuntime(),
	}
}

func detectRuntime() string {
	if _, err := exec.LookPath("kubectl"); err == nil {
		return "kubectl"
	}
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	if _, err := exec.LookPath("crictl"); err == nil {
		return "crictl"
	}
	if _, err := exec.LookPath("nerdctl"); err == nil {
		return "nerdctl"
	}
	return ""
}

func (s *Scanner) SetExpirySoonDays(days int) {
	s.expirySoonDays = days
}

func (s *Scanner) SetMinKeySize(size int) {
	s.minKeySize = size
}

func (s *Scanner) SetRuntime(runtime string) {
	s.runtime = runtime
}

var CertPaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/certs/ca-bundle.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	"/etc/kubernetes/pki/ca.crt",
	"/etc/kubernetes/pki/apiserver.crt",
	"/etc/kubernetes/pki/front-proxy-ca.crt",
}

var CertDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/certs",
	"/etc/tls",
	"/ssl",
	"/app/certs",
	"/secrets/tls",
}

func (s *Scanner) ScanContainer(container string, namespace string) (*CBOM, error) {
	if s.runtime == "" {
		return nil, fmt.Errorf("no container runtime found (kubectl, docker, crictl)")
	}

	cbom := &CBOM{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Container:    container,
		Namespace:    namespace,
		Certificates: []Certificate{},
	}

	var scannedPaths []string

	for _, path := range CertPaths {
		data, err := s.execInContainer(container, namespace, "cat", path)
		if err != nil {
			continue
		}
		scannedPaths = append(scannedPaths, path)
		certs := s.parsePEMData(data, path)
		cbom.Certificates = append(cbom.Certificates, certs...)
	}

	for _, dir := range CertDirs {
		files, err := s.execInContainer(container, namespace, "find", dir, "-name", "*.crt", "-o", "-name", "*.pem", "-type", "f")
		if err != nil {
			continue
		}
		for _, file := range strings.Split(strings.TrimSpace(string(files)), "\n") {
			if file == "" {
				continue
			}
			data, err := s.execInContainer(container, namespace, "cat", file)
			if err != nil {
				continue
			}
			scannedPaths = append(scannedPaths, file)
			certs := s.parsePEMData(data, file)
			cbom.Certificates = append(cbom.Certificates, certs...)
		}
	}

	cbom.Certificates = deduplicateCerts(cbom.Certificates)
	cbom.Summary = s.calculateSummary(cbom.Certificates)
	cbom.Summary.PathsScanned = scannedPaths

	return cbom, nil
}

func (s *Scanner) ScanPod(pod, namespace, containerName string) (*CBOM, error) {
	if s.runtime != "kubectl" {
		return nil, fmt.Errorf("pod scanning requires kubectl")
	}

	container := pod
	if containerName != "" {
		container = fmt.Sprintf("%s -c %s", pod, containerName)
	}

	return s.ScanContainer(container, namespace)
}

func (s *Scanner) execInContainer(container, namespace string, command ...string) ([]byte, error) {
	var cmd *exec.Cmd

	switch s.runtime {
	case "kubectl":
		args := []string{"exec"}
		if namespace != "" {
			args = append(args, "-n", namespace)
		}
		args = append(args, container, "--")
		args = append(args, command...)
		cmd = exec.Command("kubectl", args...)

	case "docker":
		args := []string{"exec", container}
		args = append(args, command...)
		cmd = exec.Command("docker", args...)

	case "crictl":
		args := []string{"exec", container}
		args = append(args, command...)
		cmd = exec.Command("crictl", args...)

	case "nerdctl":
		args := []string{"exec", container}
		args = append(args, command...)
		cmd = exec.Command("nerdctl", args...)

	default:
		return nil, fmt.Errorf("unsupported runtime: %s", s.runtime)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

func (s *Scanner) parsePEMData(data []byte, source string) []Certificate {
	var certs []Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				data = rest
				continue
			}
			certs = append(certs, s.parseCertificate(cert, source))
		}
		data = rest
	}

	return certs
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
		Container:    addr,
		Certificates: []Certificate{},
	}

	return cbom, nil
}

func (s *Scanner) ParsePEM(pemData []byte, source string) (*CBOM, error) {
	cbom := &CBOM{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Certificates: s.parsePEMData(pemData, source),
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
		Path:         source,
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
		c.KeySize = 256
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

func deduplicateCerts(certs []Certificate) []Certificate {
	seen := make(map[string]bool)
	var unique []Certificate
	for _, c := range certs {
		if !seen[c.Fingerprint] {
			seen[c.Fingerprint] = true
			unique = append(unique, c)
		}
	}
	return unique
}

func (c *CBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func (c *CBOM) PrintReport() string {
	workload := c.Container
	if c.Namespace != "" {
		workload = fmt.Sprintf("%s/%s", c.Namespace, c.Container)
	}

	report := fmt.Sprintf(`Certificate Bill of Materials (CBOM)
Generated:  %s
Container:  %s

SUMMARY
  Total Certificates: %d
  Expired:            %d
  Expiring Soon:      %d
  Weak Algorithm:     %d
  Short Key Length:   %d
  Self-Signed:        %d
  Paths Scanned:      %d
`, c.GeneratedAt, workload, c.Summary.Total, c.Summary.Expired,
		c.Summary.ExpiringSoon, c.Summary.WeakAlgorithm,
		c.Summary.ShortKeyLength, c.Summary.SelfSigned,
		len(c.Summary.PathsScanned))

	if c.Summary.Total == 0 {
		report += "\nNo certificates found.\n"
		return report
	}

	report += "\nCERTIFICATES\n"

	for i, cert := range c.Certificates {
		status := "OK"
		if len(cert.Issues) > 0 {
			status = strings.Join(cert.Issues, ", ")
		}

		report += fmt.Sprintf(`
  [%d] %s
      Subject:    %s
      Issuer:     %s
      Expires:    %s (%d days)
      Algorithm:  %s %d-bit
      Status:     %s
`, i+1, cert.Path, truncateStr(cert.Subject, 60), truncateStr(cert.Issuer, 60),
			cert.NotAfter.Format("2006-01-02"), cert.DaysToExpiry,
			cert.KeyAlgorithm, cert.KeySize, status)
	}

	return report
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
