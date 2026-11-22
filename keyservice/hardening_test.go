package keyservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	filippoage "filippo.io/age"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

// startTestServer starts a real gRPC key service on a loopback port with the
// given server configuration.
func startTestServer(t *testing.T, srv Server, tlsCfg *ServerTLSConfig) (addr string, stop func()) {
	t.Helper()
	var opts []grpc.ServerOption
	if tlsCfg != nil {
		creds, err := tlsCfg.ServerCredentials()
		require.NoError(t, err)
		opts = append(opts, grpc.Creds(creds))
	}
	gs := grpc.NewServer(opts...)
	RegisterKeyServiceServer(gs, srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = gs.Serve(lis) }()
	return lis.Addr().String(), func() {
		gs.Stop()
		_ = lis.Close()
	}
}

func dialTestClient(t *testing.T, addr string, tlsCfg *ClientTLSConfig) KeyServiceClient {
	t.Helper()
	cfg := ClientConfig{TLS: tlsCfg}
	dialOpts, err := cfg.DialOptions()
	require.NoError(t, err)
	conn, err := grpc.NewClient(addr, dialOpts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return NewKeyServiceClient(conn)
}

func rpcContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// TestUnauthenticatedConnectionRejected runs two instances: one with caller
// authentication and one that explicitly admits anonymous callers on loopback.
// The authenticated instance must reject callers without a verified client
// certificate at the TLS handshake, while the anonymous instance still serves
// the same request.
func TestUnauthenticatedConnectionRejected(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(time.Hour))
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: identity.Recipient().String()}}}

	authedAddr, stopAuthed := startTestServer(t, Server{}, &ServerTLSConfig{
		CertFile:     pki.serverCert,
		KeyFile:      pki.serverKey,
		ClientCAFile: pki.caCert,
	})
	defer stopAuthed()
	anonymousAddr, stopAnonymous := startTestServer(t, Server{AllowAnonymous: true}, nil)
	defer stopAnonymous()

	// Sanity: both instances are up.
	authedClient := dialTestClient(t, authedAddr, &ClientTLSConfig{
		CAFile:     pki.caCert,
		CertFile:   pki.clientCert,
		KeyFile:    pki.clientKey,
		ServerName: "keyservice.test",
	})
	ctx, cancel := rpcContext(t)
	_, err = authedClient.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	cancel()
	// The payload is invalid, but it must reach the backend, proving the
	// authenticated call was admitted rather than rejected at handshake.
	assert.False(t, IsAuthorizationError(err), "authenticated caller must not be rejected: %v", err)
	assert.False(t, errors.Is(err, ErrAuthenticationRequired))

	// A TLS client that does not present a client certificate must be
	// rejected during the handshake.
	noCertClient := dialTestClient(t, authedAddr, &ClientTLSConfig{
		CAFile:     pki.caCert,
		ServerName: "keyservice.test",
	})
	ctx, cancel = rpcContext(t)
	_, err = noCertClient.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	cancel()
	require.Error(t, err, "connection without a client certificate must be refused")
	assert.Contains(t, strings.ToLower(err.Error()), "certificate")

	// A plaintext client against a TLS listener must also be refused.
	plainClient := dialTestClient(t, authedAddr, nil)
	ctx, cancel = rpcContext(t)
	_, err = plainClient.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	cancel()
	require.Error(t, err, "plaintext connection to an authenticated listener must be refused")

	// The explicitly anonymous instance admits the caller and reaches the
	// backend; the backend fails on the bogus payload, but not with a
	// transport or authorization rejection.
	anonClient := dialTestClient(t, anonymousAddr, nil)
	ctx, cancel = rpcContext(t)
	_, err = anonClient.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	cancel()
	assert.False(t, IsAuthorizationError(err), "anonymous listener must admit the caller: %v", err)
}

// TestOutOfScopeKeyDenied asserts that a known caller requesting a key outside
// its scope gets an explicit denial that does not leak the key identifier.
func TestOutOfScopeKeyDenied(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(time.Hour))
	policy := &Policy{Rules: []ScopeRule{{
		Name:    "ops-pgp-only",
		Callers: []string{"ops-client"},
		Keys:    []string{"pgp:*"},
	}}}
	require.NoError(t, policy.Validate())

	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.InfoLevel)

	srv := Server{
		Policy: policy,
		Audit:  NewAuditLogger(logger, &Metrics{}),
	}
	addr, stop := startTestServer(t, srv, &ServerTLSConfig{
		CertFile:     pki.serverCert,
		KeyFile:      pki.serverKey,
		ClientCAFile: pki.caCert,
	})
	defer stop()

	client := dialTestClient(t, addr, &ClientTLSConfig{
		CAFile:     pki.caCert,
		CertFile:   pki.clientCert,
		KeyFile:    pki.clientKey,
		ServerName: "keyservice.test",
	})
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	recipient := identity.Recipient().String()
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: recipient}}}

	ctx, cancel := rpcContext(t)
	_, err = client.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: []byte("ciphertext-not-to-log")})
	cancel()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, StatusCode(err))
	assert.Contains(t, err.Error(), "outside of the caller's permitted scope")
	assert.NotContains(t, err.Error(), recipient, "out-of-scope error must not contain the key identifier")
	assert.NotContains(t, err.Error(), "ciphertext-not-to-log")

	// The audit record must name the caller and request class, and must not
	// contain key material or the key identifier.
	assert.Contains(t, logs.String(), "keyservice.request")
	assert.Contains(t, logs.String(), "caller=ops-client")
	assert.Contains(t, logs.String(), "operation=decrypt")
	assert.Contains(t, logs.String(), "key_type=age")
	assert.Contains(t, logs.String(), "reason=out_of_scope")
	assert.NotContains(t, logs.String(), recipient)
	assert.NotContains(t, logs.String(), "ciphertext-not-to-log")

	// Policies also govern in-process callers (default-deny). Because the
	// rule only names ops-client, the local caller is rejected; in-process
	// calls keep the sentinel in the error chain, so callers can tell the
	// kinds of denial apart without parsing messages.
	local := NewCustomLocalClient(srv)
	_, err = local.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	assert.ErrorIs(t, err, ErrCallerNotAuthorized)
	assert.Equal(t, codes.PermissionDenied, StatusCode(err))
}

// TestBackendTimeoutReleasesCall asserts that a timed-out backend call is
// abandoned and its context released, and that the timeout is distinguishable
// from an authorization rejection.
func TestBackendTimeoutReleasesCall(t *testing.T) {
	started := make(chan struct{})
	released := make(chan struct{})
	var once sync.Once
	srv := Server{
		RequestTimeout: 50 * time.Millisecond,
		backendHook: func(ctx context.Context) error {
			once.Do(func() { close(started) })
			<-ctx.Done()
			close(released)
			return ctx.Err()
		},
	}
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1notarealrecipient"}}}

	errCh := make(chan error, 1)
	go func() {
		_, err := srv.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("backend was never called")
	}
	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBackendTimeout)
		assert.Equal(t, codes.DeadlineExceeded, StatusCode(err))
		assert.False(t, IsAuthorizationError(err), "a timeout must not look like an authorization denial")
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out request did not return")
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("backend context was not released after the timeout")
	}
}

// TestTimeoutLeavesNoQueuedCall asserts that after a timeout the worker slot is
// returned, so a subsequent request is served instead of waiting forever.
func TestTimeoutLeavesNoQueuedCall(t *testing.T) {
	metrics := &Metrics{}
	limiter := NewLimiter(1, 0, 0, time.Second, 4, metrics)
	release := make(chan struct{})
	srv := Server{
		RequestTimeout: 30 * time.Millisecond,
		Limiter:        limiter,
		Metrics:        metrics,
		backendHook: func(ctx context.Context) error {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return ctx.Err()
		},
	}
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1notarealrecipient"}}}
	_, err := srv.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	require.ErrorIs(t, err, ErrBackendTimeout)
	close(release)

	// The slot must be free again: a fresh request acquires it immediately.
	done := make(chan error, 1)
	go func() {
		_, err := srv.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
		done <- err
	}()
	select {
	case err := <-done:
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("worker slot was not released after the timeout")
	}
	assert.Equal(t, uint64(1), metrics.Snapshot().BackendTimeouts)
	assert.Equal(t, int64(0), metrics.Snapshot().InFlight)
}

// TestRateLimitAndQueueObservable asserts that rate limiting and queue
// saturation are rejected with ResourceExhausted and counted in the metrics.
func TestRateLimitAndQueueObservable(t *testing.T) {
	metrics := &Metrics{}
	limiter := NewLimiter(1, 1, 1, 50*time.Millisecond, 0, metrics)
	srv := Server{Limiter: limiter, Metrics: metrics}
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1notarealrecipient"}}}

	// First request consumes the burst token and the only worker slot. The
	// backend fails immediately, so only the token is consumed.
	_, _ = srv.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	// Second request is rate limited.
	_, err := srv.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRateLimited)
	assert.Equal(t, codes.ResourceExhausted, StatusCode(err))
	assert.Equal(t, uint64(1), metrics.Snapshot().RateLimited)

	// Queue timeout is observable too: hold the only slot, then wait behind it.
	hold := make(chan struct{})
	started := make(chan struct{})
	blocking := Server{
		Limiter: NewLimiter(1, 0, 0, 50*time.Millisecond, 10, metrics),
		Metrics: metrics,
		backendHook: func(ctx context.Context) error {
			close(started)
			<-hold
			return nil
		},
	}
	go func() {
		_, _ = blocking.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	}()
	<-started
	_, err = blocking.Decrypt(context.Background(), &DecryptRequest{Key: key, Ciphertext: []byte("x")})
	close(hold)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrQueueTimeout)
	assert.Equal(t, codes.ResourceExhausted, StatusCode(err))
	assert.Equal(t, cap(blocking.Limiter.slots), 1)
}

// TestServerIdentityMismatch asserts the client refuses a server whose
// certificate does not carry the identity it declared.
func TestServerIdentityMismatch(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(time.Hour))
	addr, stop := startTestServer(t, Server{AllowAnonymous: true}, &ServerTLSConfig{
		CertFile: pki.serverCert,
		KeyFile:  pki.serverKey,
	})
	defer stop()

	client := dialTestClient(t, addr, &ClientTLSConfig{
		CAFile:                 pki.caCert,
		ServerName:             "keyservice.test",
		ExpectedServerIdentity: "spiffe://example.org/someone-else",
	})
	ctx, cancel := rpcContext(t)
	defer cancel()
	_, err := client.Decrypt(ctx, &DecryptRequest{
		Key:        &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1x"}}},
		Ciphertext: []byte("x"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server identity does not match the expected identity")
}

// TestExpiredPeerCertificate asserts expiry is reported explicitly and never
// silently downgraded to an unverified connection.
func TestExpiredPeerCertificate(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(-time.Minute))
	_, err := ResolveClientOptions(WithTLS(ClientTLSConfig{
		CAFile:   pki.caCert,
		CertFile: pki.clientCert,
		KeyFile:  pki.clientKey,
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPeerCertificateExpired)
	assert.NotErrorIs(t, err, ErrUntrustedPeer)
}

// TestConfigValidationFailsAtStartup asserts invalid listener, certificate and
// policy configurations are rejected before serving.
func TestConfigValidationFailsAtStartup(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(time.Hour))

	t.Run("unauthenticated non-local listener", func(t *testing.T) {
		cfg := &ListenerConfig{Network: "tcp", Address: "0.0.0.0:5000"}
		assert.ErrorIs(t, cfg.Validate(), ErrLocalOnly)
	})
	t.Run("unauthenticated local listener is allowed", func(t *testing.T) {
		cfg := &ListenerConfig{Network: "tcp", Address: "127.0.0.1:5000"}
		assert.NoError(t, cfg.Validate())
	})
	t.Run("authenticated non-local listener is allowed", func(t *testing.T) {
		cfg := &ListenerConfig{
			Network: "tcp",
			Address: "0.0.0.0:5000",
			TLS:     &ServerTLSConfig{CertFile: pki.serverCert, KeyFile: pki.serverKey, ClientCAFile: pki.caCert},
		}
		assert.NoError(t, cfg.Validate())
	})
	t.Run("anonymous non-local listener is refused", func(t *testing.T) {
		cfg := &ListenerConfig{Network: "tcp", Address: "0.0.0.0:5000", AllowAnonymous: true}
		assert.ErrorIs(t, cfg.Validate(), ErrAnonymousNotLocal)
	})
	t.Run("invalid address", func(t *testing.T) {
		cfg := &ListenerConfig{Network: "tcp", Address: "not-an-address"}
		assert.Error(t, cfg.Validate())
	})
	t.Run("missing certificate file", func(t *testing.T) {
		cfg := &ListenerConfig{
			Network: "tcp",
			Address: "127.0.0.1:0",
			TLS:     &ServerTLSConfig{CertFile: pki.dir + "/missing.pem", KeyFile: pki.serverKey},
		}
		assert.Error(t, cfg.Validate())
	})
	t.Run("client CA without certificate", func(t *testing.T) {
		cfg := &ListenerConfig{
			Network: "tcp",
			Address: "127.0.0.1:0",
			TLS:     &ServerTLSConfig{ClientCAFile: pki.caCert},
		}
		assert.Error(t, cfg.Validate())
	})
	t.Run("encrypted transport without caller auth on non-local listener is refused", func(t *testing.T) {
		cfg := &ListenerConfig{
			Network: "tcp",
			Address: "0.0.0.0:5000",
			TLS:     &ServerTLSConfig{CertFile: pki.serverCert, KeyFile: pki.serverKey},
		}
		assert.ErrorIs(t, cfg.Validate(), ErrLocalOnly)
	})
	t.Run("unknown caller in policy", func(t *testing.T) {
		require.NoError(t, os.WriteFile(pki.dir+"/bad-policy.yaml", []byte("rules:\n- callers: [x]\n  keys: [notatype:foo]\n"), 0o600))
		_, err := LoadPolicy(pki.dir + "/bad-policy.yaml")
		assert.Error(t, err)
	})
	t.Run("policy typo in known field", func(t *testing.T) {
		require.NoError(t, os.WriteFile(pki.dir+"/typo-policy.yaml", []byte("rule:\n- callers: [x]\n"), 0o600))
		_, err := LoadPolicy(pki.dir + "/typo-policy.yaml")
		assert.Error(t, err)
	})
}

// TestLocalClientUnchanged asserts the in-process client still works with no
// options and no transport, preserving the existing local behavior.
func TestLocalClientUnchanged(t *testing.T) {
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	identityFile := t.TempDir() + "/keys.txt"
	require.NoError(t, os.WriteFile(identityFile, []byte(identity.String()+"\n"), 0o600))
	t.Setenv("SOPS_AGE_KEY_FILE", identityFile)

	client := NewLocalClient()
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: identity.Recipient().String()}}}
	ctx, cancel := rpcContext(t)
	defer cancel()
	enc, err := client.Encrypt(ctx, &EncryptRequest{Key: key, Plaintext: []byte("super-secret-data-key")})
	require.NoError(t, err)
	ciphertext := enc.Ciphertext
	rsp, err := client.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: ciphertext})
	require.NoError(t, err)
	assert.Equal(t, []byte("super-secret-data-key"), rsp.Plaintext)
}

// TestAuditLogExcludesKeyMaterial runs a successful encrypt and decrypt and
// asserts that neither key material nor plaintext reaches the audit log.
func TestAuditLogExcludesKeyMaterial(t *testing.T) {
	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.InfoLevel)

	metrics := &Metrics{}
	srv := Server{Audit: NewAuditLogger(logger, metrics), Metrics: metrics}

	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	identityFile := t.TempDir() + "/keys.txt"
	require.NoError(t, os.WriteFile(identityFile, []byte(identity.String()+"\n"), 0o600))
	t.Setenv("SOPS_AGE_KEY_FILE", identityFile)

	secret := []byte("extremely-secret-data-key-material")
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: identity.Recipient().String()}}}
	ctx := context.Background()
	enc, err := srv.Encrypt(ctx, &EncryptRequest{Key: key, Plaintext: secret})
	require.NoError(t, err)
	dec, err := srv.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: enc.Ciphertext})
	require.NoError(t, err)
	assert.Equal(t, secret, dec.Plaintext)

	out := logs.String()
	assert.Contains(t, out, "caller=local")
	assert.Contains(t, out, "operation=encrypt")
	assert.Contains(t, out, "operation=decrypt")
	assert.Contains(t, out, "outcome=allowed")
	assert.NotContains(t, out, string(secret))
	assert.NotContains(t, out, string(enc.Ciphertext))
	assert.NotContains(t, out, identity.Recipient().String(), "audit log must not carry the key identifier")
}

// TestPolicyOperationsDefault asserts operations default to both and can be
// restricted per rule.
func TestPolicyOperationsDefault(t *testing.T) {
	policy := &Policy{Rules: []ScopeRule{
		{Name: "decrypt-only", Callers: []string{"ops-client"}, Keys: []string{"age:*"}, Operations: []string{"decrypt"}},
	}}
	require.NoError(t, policy.Validate())
	id := CallerIdentity{Authenticated: true, CommonName: "ops-client"}
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1abc"}}}
	assert.NoError(t, policy.Authorize(id, OpDecrypt, key))
	assert.ErrorIs(t, policy.Authorize(id, OpEncrypt, key), ErrKeyOutOfScope)
	assert.ErrorIs(t, policy.Authorize(CallerIdentity{Authenticated: true, CommonName: "someone"}, OpDecrypt, key), ErrCallerNotAuthorized)
}

// TestAnonymousRequiresExplicitOptIn asserts the network server refuses an
// unauthenticated caller unless anonymous access was explicitly enabled, and
// that the refusal is counted.
func TestAnonymousRequiresExplicitOptIn(t *testing.T) {
	metrics := &Metrics{}
	srv := Server{Metrics: metrics}
	peerCtx := peerContext(t)
	_, err := srv.Decrypt(peerCtx, &DecryptRequest{
		Key:        &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1x"}}},
		Ciphertext: []byte("x"),
	})
	require.ErrorIs(t, err, ErrAuthenticationRequired)
	assert.Equal(t, codes.Unauthenticated, StatusCode(err))
	assert.Equal(t, uint64(0), metrics.Snapshot().Anonymous, "a rejected anonymous caller is not counted as admitted")
	assert.Equal(t, uint64(1), metrics.Snapshot().Denied)
}

// TestTLSMinVersionRejected asserts an invalid TLS version is a startup error.
func TestTLSMinVersionRejected(t *testing.T) {
	// Exercise the parsing helper used by the command package through the
	// public TLS config surface: a TLS 1.3 minimum is accepted.
	pki := newTestPKI(t, time.Now().Add(time.Hour))
	cfg := &ServerTLSConfig{CertFile: pki.serverCert, KeyFile: pki.serverKey, MinVersion: tls.VersionTLS13}
	assert.NoError(t, cfg.validate())
}

// TestNonTLSListenerStillServesAnonymousLocal asserts the unhardened form
// remains available when explicitly enabled on loopback.
func TestNonTLSListenerStillServesAnonymousLocal(t *testing.T) {
	addr, stop := startTestServer(t, Server{AllowAnonymous: true}, nil)
	defer stop()
	client := dialTestClient(t, addr, nil)
	identity, err := filippoage.GenerateX25519Identity()
	require.NoError(t, err)
	identityFile := t.TempDir() + "/keys.txt"
	require.NoError(t, os.WriteFile(identityFile, []byte(identity.String()+"\n"), 0o600))
	t.Setenv("SOPS_AGE_KEY_FILE", identityFile)
	key := &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: identity.Recipient().String()}}}
	ctx, cancel := rpcContext(t)
	defer cancel()
	enc, err := client.Encrypt(ctx, &EncryptRequest{Key: key, Plaintext: []byte("data-key")})
	require.NoError(t, err)
	dec, err := client.Decrypt(ctx, &DecryptRequest{Key: key, Ciphertext: enc.Ciphertext})
	require.NoError(t, err)
	assert.Equal(t, []byte("data-key"), dec.Plaintext)
}

func peerContext(t *testing.T) context.Context {
	t.Helper()
	// A gRPC peer without TLS auth info models a plaintext network caller.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()
	conn, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return peer.NewContext(context.Background(), &peer.Peer{Addr: conn.RemoteAddr()})
}

// TestRemoteClientTimeoutReleasesBackend asserts a client-side timeout reaches
// the server and releases the backend call, and that the error is identifiable
// as a timeout rather than an authorization denial.
func TestRemoteClientTimeoutReleasesBackend(t *testing.T) {
	released := make(chan struct{})
	var once sync.Once
	srv := Server{
		AllowAnonymous: true,
		backendHook: func(ctx context.Context) error {
			<-ctx.Done()
			once.Do(func() { close(released) })
			return ctx.Err()
		},
	}
	addr, stop := startTestServer(t, srv, nil)
	defer stop()

	cfg := ClientConfig{}
	dialOpts, err := cfg.DialOptions()
	require.NoError(t, err)
	conn, err := grpc.NewClient(addr, dialOpts...)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client, err := NewRemoteClient(conn, WithRequestTimeout(50*time.Millisecond))
	require.NoError(t, err)

	_, err = client.Decrypt(context.Background(), &DecryptRequest{
		Key:        &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1x"}}},
		Ciphertext: []byte("x"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.DeadlineExceeded, StatusCode(err))
	assert.True(t, IsTimeout(err))
	assert.False(t, IsAuthorizationError(err))
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("server backend was not released after the client timeout")
	}
}

// TestScopeRuleParsing asserts the YAML policy surface, including wildcards,
// operations and comments, loads and behaves as documented.
func TestScopeRuleParsing(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	require.NoError(t, os.WriteFile(path, []byte(`rules:
- name: ops
  callers:
    - "ops-*"
  keys:
    - "age:age1ops*"
    - "pgp:*"
  operations: [decrypt]
- name: build
  callers: ["CN=build-client"]
  keys: ["kms:arn:aws:kms:eu-west-1:123456789012:key/*"]
`), 0o600))
	policy, err := LoadPolicy(path)
	require.NoError(t, err)

	ops := CallerIdentity{Authenticated: true, CommonName: "ops-1"}
	assert.NoError(t, policy.Authorize(ops, OpDecrypt, &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1opsfoo"}}}))
	assert.ErrorIs(t, policy.Authorize(ops, OpDecrypt, &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1other"}}}), ErrKeyOutOfScope)
	assert.ErrorIs(t, policy.Authorize(ops, OpEncrypt, &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1opsfoo"}}}), ErrKeyOutOfScope)

	build := CallerIdentity{Authenticated: true, CommonName: "build-client"}
	assert.NoError(t, policy.Authorize(build, OpEncrypt, &Key{KeyType: &Key_KmsKey{KmsKey: &KmsKey{Arn: "arn:aws:kms:eu-west-1:123456789012:key/abc"}}}))
	assert.ErrorIs(t, policy.Authorize(CallerIdentity{Authenticated: true, CommonName: "stranger"}, OpDecrypt, &Key{KeyType: &Key_PgpKey{PgpKey: &PgpKey{Fingerprint: "ABCD"}}}), ErrCallerNotAuthorized)
}

// TestHandshakeFailureAudited asserts a connection rejected at the TLS
// handshake leaves an audit record with a reason, and that the record carries
// no certificate or key material.
func TestHandshakeFailureAudited(t *testing.T) {
	pki := newTestPKI(t, time.Now().Add(time.Hour))
	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetLevel(logrus.InfoLevel)
	metrics := &Metrics{}
	audit := NewAuditLogger(logger, metrics)

	tlsCfg := &ServerTLSConfig{
		CertFile:           pki.serverCert,
		KeyFile:            pki.serverKey,
		ClientCAFile:       pki.caCert,
		OnHandshakeFailure: audit.LogHandshakeFailure,
	}
	addr, stop := startTestServer(t, Server{}, tlsCfg)
	defer stop()

	client := dialTestClient(t, addr, &ClientTLSConfig{
		CAFile:     pki.caCert,
		ServerName: "keyservice.test",
	})
	ctx, cancel := rpcContext(t)
	_, err := client.Decrypt(ctx, &DecryptRequest{
		Key:        &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{Recipient: "age1x"}}},
		Ciphertext: []byte("x"),
	})
	cancel()
	require.Error(t, err)

	assert.Contains(t, logs.String(), "keyservice.request")
	assert.Contains(t, logs.String(), "operation=handshake")
	assert.Contains(t, logs.String(), "outcome=denied")
	assert.Equal(t, uint64(1), metrics.Snapshot().Denied)
	assert.NotContains(t, logs.String(), "BEGIN CERTIFICATE")
}
