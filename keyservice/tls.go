package keyservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"
)

// ListenerConfig describes where and how the key service listens. It is
// validated before any socket is opened so that misconfiguration fails at
// startup.
type ListenerConfig struct {
	// Network is "tcp" or "unix".
	Network string
	// Address is a host:port for tcp, or a path for unix.
	Address string
	// TLS enables an encrypted, peer-verified transport when set.
	TLS *ServerTLSConfig
	// AllowAnonymous explicitly admits unauthenticated network callers.
	// It is refused for non-local listeners because an unauthenticated
	// service must never be reachable from outside the machine.
	AllowAnonymous bool
}

// ServerTLSConfig holds the certificate material used by the key service.
type ServerTLSConfig struct {
	CertFile string
	KeyFile  string
	// ClientCAFile enables caller authentication. When set, every
	// connection must present a client certificate that chains to this CA
	// or the TLS handshake is rejected.
	ClientCAFile string
	// MinVersion overrides the minimum TLS version (default TLS 1.2).
	MinVersion uint16
	// OnHandshakeFailure, when set, is called with the peer address and a
	// sanitized reason for every refused handshake, so failed
	// authentication is auditable.
	OnHandshakeFailure func(peer, reason string)
}

// Enabled reports whether transport encryption is configured.
func (c *ServerTLSConfig) Enabled() bool {
	return c != nil && c.CertFile != ""
}

// configured reports whether any TLS field was set, even if incomplete. It is
// used to prefer a validation error over silently ignoring partial config.
func (c *ServerTLSConfig) configured() bool {
	return c != nil && (c.CertFile != "" || c.KeyFile != "" || c.ClientCAFile != "")
}

// AuthenticatesCallers reports whether client certificates are required and
// verified.
func (c *ServerTLSConfig) AuthenticatesCallers() bool {
	return c != nil && c.ClientCAFile != ""
}

// Validate checks the TLS configuration and the listener address. Expired or
// malformed certificate material is rejected at startup.
func (c *ListenerConfig) Validate() error {
	if c == nil {
		return errors.New("keyservice: missing listener configuration")
	}
	switch c.Network {
	case "", "tcp", "tcp4", "tcp6", "unix", "unixpacket":
	default:
		return fmt.Errorf("keyservice: unsupported network %q", c.Network)
	}
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("keyservice: listener address must not be empty")
	}
	if isUnixNetwork(c.Network) {
		if c.TLS.Enabled() {
			// TLS over a unix socket is allowed but unnecessary; still
			// validate the material below.
			_ = c.TLS
		}
	} else {
		if _, _, err := net.SplitHostPort(c.Address); err != nil {
			return fmt.Errorf("keyservice: invalid listen address %q: %w", c.Address, err)
		}
	}
	if c.TLS.configured() {
		if err := c.TLS.validate(); err != nil {
			return err
		}
	}
	if c.AllowAnonymous && !isLocalListener(c.Network, c.Address) {
		return ErrAnonymousNotLocal
	}
	if !c.TLS.AuthenticatesCallers() {
		// Default-deny boundary: without caller authentication (whether
		// plaintext or TLS without a client CA) the service must not be
		// reachable from outside the local machine, unless it is a unix
		// socket protected by filesystem permissions. Merely encrypting the
		// transport does not identify the caller.
		if !isLocalListener(c.Network, c.Address) {
			return ErrLocalOnly
		}
	}
	return nil
}

func (c *ServerTLSConfig) validate() error {
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("keyservice: both TLS certificate and key files are required")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return fmt.Errorf("keyservice: cannot load TLS certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("keyservice: TLS certificate file contains no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("keyservice: cannot parse TLS certificate: %w", err)
	}
	if !certValidAt(leaf, time.Now()) {
		return fmt.Errorf("%w: server certificate %q not valid at %s", ErrPeerCertificateExpired, c.CertFile, time.Now().Format(time.RFC3339))
	}
	if c.ClientCAFile != "" {
		if _, err := loadCertPool(c.ClientCAFile); err != nil {
			return err
		}
	}
	return nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyservice: cannot read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("keyservice: no valid certificates found in %q", path)
	}
	return pool, nil
}

func isUnixNetwork(network string) bool {
	return network == "unix" || network == "unixpacket"
}

// isLocalListener reports whether the listener can only be reached from the
// local machine: unix sockets, loopback IPs and localhost.
func isLocalListener(network, address string) bool {
	if isUnixNetwork(network) {
		return true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "" {
		// ":5000" binds every interface.
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// ServerCredentials builds the gRPC transport credentials for the listener.
// It is only called after ListenerConfig.Validate succeeded.
func (c *ServerTLSConfig) ServerCredentials() (credentials.TransportCredentials, error) {
	if !c.Enabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("keyservice: cannot load TLS certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   c.MinVersion,
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	if c.ClientCAFile != "" {
		clientCAs, err := loadCertPool(c.ClientCAFile)
		if err != nil {
			return nil, err
		}
		// RequireAndVerifyClientCert makes the TLS stack verify the chain,
		// expiry and client-auth usage during the handshake and reject the
		// connection when verification fails. The additional callback keeps
		// our precise error classification; it cannot turn a verification
		// failure into a success, so a failed check never falls back to an
		// unverified connection.
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAs
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) > 0 {
				return nil
			}
			return verifyPeerCertificates(rawCerts, clientCAs, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		}
	}
	creds := credentials.NewTLS(cfg)
	if c.OnHandshakeFailure != nil {
		// Wrap the transport so that handshake rejections -- including
		// rejections that happen before our verification callback runs (for
		// example a missing client certificate) -- are auditable.
		return &auditedServerCredentials{TransportCredentials: creds, onFailure: c.OnHandshakeFailure}, nil
	}
	return creds, nil
}

// auditedServerCredentials records refused TLS handshakes. It changes nothing
// about the handshake itself: an error is still returned and the connection is
// closed by gRPC.
type auditedServerCredentials struct {
	credentials.TransportCredentials
	onFailure func(peer, reason string)
}

func (c *auditedServerCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(rawConn)
	if err != nil && c.onFailure != nil {
		peer := ""
		if rawConn != nil && rawConn.RemoteAddr() != nil {
			peer = rawConn.RemoteAddr().String()
		}
		c.onFailure(peer, reasonForHandshakeFailure(err))
	}
	return conn, info, err
}

func (c *auditedServerCredentials) Clone() credentials.TransportCredentials {
	return &auditedServerCredentials{TransportCredentials: c.TransportCredentials.Clone(), onFailure: c.onFailure}
}

// ClientTLSConfig holds the material a client uses to verify and authenticate
// against a key service.
type ClientTLSConfig struct {
	// CAFile is the CA bundle used to verify the server certificate.
	CAFile string
	// CertFile and KeyFile optionally present a client certificate, which
	// is required by a server with caller authentication enabled.
	CertFile string
	KeyFile  string
	// ServerName is the name the client expects in the server certificate.
	ServerName string
	// ExpectedServerIdentity, when set, additionally pins the server
	// certificate to this CN, DNS SAN or URI SAN. A mismatch aborts the
	// connection.
	ExpectedServerIdentity string
	MinVersion             uint16
}

// Enabled reports whether any client TLS material was configured.
func (c *ClientTLSConfig) Enabled() bool {
	return c != nil && (c.CAFile != "" || c.CertFile != "" || c.KeyFile != "" || c.ServerName != "" || c.ExpectedServerIdentity != "")
}

// Validate checks the client TLS configuration at startup.
func (c *ClientTLSConfig) Validate() error {
	if c == nil || !c.Enabled() {
		return nil
	}
	if c.CAFile == "" {
		return errors.New("keyservice: a CA file is required to verify the key service")
	}
	if _, err := loadCertPool(c.CAFile); err != nil {
		return err
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("keyservice: both client certificate and key files are required")
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return fmt.Errorf("keyservice: cannot load client certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("keyservice: cannot parse client certificate: %w", err)
		}
		if !certValidAt(leaf, time.Now()) {
			return fmt.Errorf("%w: client certificate %q not valid at %s", ErrPeerCertificateExpired, c.CertFile, time.Now().Format(time.RFC3339))
		}
	}
	return nil
}

// DialCredentials builds the gRPC transport credentials for a client.
func (c *ClientTLSConfig) DialCredentials() (credentials.TransportCredentials, error) {
	if !c.Enabled() {
		return nil, nil
	}
	roots, err := loadCertPool(c.CAFile)
	if err != nil {
		return nil, err
	}
	base := &tls.Config{
		RootCAs:    roots,
		MinVersion: c.MinVersion,
	}
	if base.MinVersion == 0 {
		base.MinVersion = tls.VersionTLS12
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("keyservice: cannot load client certificate: %w", err)
		}
		base.Certificates = []tls.Certificate{cert}
	}
	return &verifyingCredentials{
		base:             base,
		roots:            roots,
		serverName:       c.ServerName,
		expectedIdentity: c.ExpectedServerIdentity,
	}, nil
}

// verifyingCredentials is a client transport that verifies the server
// certificate at handshake time. It captures the dialed authority so the
// expected server name defaults to it, and it never falls back to an
// unverified connection: any verification error aborts the handshake.
type verifyingCredentials struct {
	base             *tls.Config
	roots            *x509.CertPool
	serverName       string
	expectedIdentity string
}

func (c *verifyingCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	expectedName := c.serverName
	if expectedName == "" {
		expectedName = authority
		if host, _, err := net.SplitHostPort(authority); err == nil {
			expectedName = host
		}
	}
	cfg := c.base.Clone()
	cfg.InsecureSkipVerify = true
	cfg.ServerName = expectedName
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if err := verifyPeerCertificates(rawCerts, c.roots, expectedName, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
			return err
		}
		if c.expectedIdentity != "" {
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("keyservice: cannot parse server certificate: %w", err)
			}
			if !certificateHasIdentity(leaf, c.expectedIdentity) {
				return fmt.Errorf("%w: expected %q", ErrServerIdentityMismatch, c.expectedIdentity)
			}
		}
		return nil
	}
	return credentials.NewTLS(cfg).ClientHandshake(ctx, authority, rawConn)
}

func (c *verifyingCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return credentials.NewTLS(c.base).ServerHandshake(rawConn)
}

func (c *verifyingCredentials) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(c.base).Info()
}

func (c *verifyingCredentials) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

func (c *verifyingCredentials) OverrideServerName(name string) error {
	c.serverName = name
	return nil
}

// verifyPeerCertificates validates the presented chain. It never falls back to
// an unverified connection and classifies expiry and trust failures.
func verifyPeerCertificates(rawCerts [][]byte, roots *x509.CertPool, dnsName string, usages []x509.ExtKeyUsage) error {
	if len(rawCerts) == 0 {
		return ErrUntrustedPeer
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("keyservice: cannot parse peer certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	now := time.Now()
	for _, cert := range certs {
		if !certValidAt(cert, now) {
			return fmt.Errorf("%w: certificate %q not valid at %s", ErrPeerCertificateExpired, cert.Subject.CommonName, now.Format(time.RFC3339))
		}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       dnsName,
		KeyUsages:     usages,
		CurrentTime:   now,
	})
	if err == nil {
		return nil
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return fmt.Errorf("%w: %v", ErrServerIdentityMismatch, err)
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired {
		return fmt.Errorf("%w: %v", ErrPeerCertificateExpired, err)
	}
	var unknownErr x509.UnknownAuthorityError
	if errors.As(err, &unknownErr) {
		return fmt.Errorf("%w: %v", ErrUntrustedPeer, err)
	}
	return fmt.Errorf("%w: %v", ErrUntrustedPeer, err)
}

func certValidAt(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

func certificateHasIdentity(cert *x509.Certificate, identity string) bool {
	if cert.Subject.CommonName == identity {
		return true
	}
	for _, name := range cert.DNSNames {
		if name == identity || "DNS="+name == identity {
			return true
		}
	}
	for _, uri := range cert.URIs {
		if uri.String() == identity || "URI="+uri.String() == identity {
			return true
		}
	}
	return false
}
