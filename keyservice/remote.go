package keyservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Option configures a remote key service client. Options only affect remote
// clients; the in-process LocalClient is unaffected.
type Option func(*ClientConfig) error

// ClientConfig is the resolved client configuration. It is exported so that
// callers can validate it before dialing and reuse it for logging.
type ClientConfig struct {
	TLS            *ClientTLSConfig
	RequestTimeout time.Duration
}

// WithTLS enables encrypted, peer-verified transport for a remote client.
// When ExpectedServerIdentity is set, a server certificate that does not carry
// that identity aborts the connection.
func WithTLS(cfg ClientTLSConfig) Option {
	return func(c *ClientConfig) error {
		c.TLS = &cfg
		return nil
	}
}

// WithRequestTimeout sets a per-request deadline. When it expires the RPC
// returns DeadlineExceeded and the remote server releases the backend call.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *ClientConfig) error {
		if timeout < 0 {
			return fmt.Errorf("keyservice: request timeout must not be negative")
		}
		c.RequestTimeout = timeout
		return nil
	}
}

// ResolveClientOptions applies and validates the options. It is called at
// startup so that a missing CA, malformed client certificate or expired
// certificate fails before any request is made.
func ResolveClientOptions(opts ...Option) (ClientConfig, error) {
	cfg := ClientConfig{}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return cfg, err
		}
	}
	if cfg.TLS.Enabled() {
		if err := cfg.TLS.Validate(); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// DialOptions returns the gRPC dial options for the resolved configuration.
// Without TLS material the previous insecure transport is preserved, which
// keeps existing clients able to reach unhardened instances.
func (c ClientConfig) DialOptions() ([]grpc.DialOption, error) {
	if !c.TLS.Enabled() {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	creds, err := c.TLS.DialCredentials()
	if err != nil {
		return nil, err
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}, nil
}

// remoteClient wraps the generated client with a per-request deadline.
type remoteClient struct {
	KeyServiceClient
	timeout time.Duration
}

func (c remoteClient) Decrypt(ctx context.Context, req *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.KeyServiceClient.Decrypt(ctx, req, opts...)
}

func (c remoteClient) Encrypt(ctx context.Context, req *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.KeyServiceClient.Encrypt(ctx, req, opts...)
}

// NewRemoteClient wraps an existing gRPC connection with the resolved client
// configuration. The connection's own dial options are the caller's
// responsibility.
func NewRemoteClient(conn grpc.ClientConnInterface, opts ...Option) (KeyServiceClient, error) {
	cfg, err := ResolveClientOptions(opts...)
	if err != nil {
		return nil, err
	}
	return remoteClient{KeyServiceClient: NewKeyServiceClient(conn), timeout: cfg.RequestTimeout}, nil
}

// StatusCode returns the gRPC status code for err, or codes.OK.
func StatusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	return status.Code(err)
}

// IsAuthorizationError reports whether err is a decision of the key service to
// refuse the caller (unauthenticated or out of scope), as opposed to a backend
// failure or a timeout.
func IsAuthorizationError(err error) bool {
	switch StatusCode(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}

// IsTimeout reports whether err is a request or backend timeout.
func IsTimeout(err error) bool {
	return StatusCode(err) == codes.DeadlineExceeded || errors.Is(err, ErrBackendTimeout)
}
