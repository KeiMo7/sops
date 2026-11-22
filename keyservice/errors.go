package keyservice

import "errors"

// Errors returned by the key service authorization, limiting and backend
// layers. They are intentionally free of key identifiers and key material so
// that they can safely be returned to callers and written to logs.
var (
	// ErrAuthenticationRequired is returned when the server requires a
	// verified caller identity but the connection does not carry one.
	ErrAuthenticationRequired = errors.New("keyservice: caller authentication is required")

	// ErrCallerNotAuthorized is returned when the caller identity is valid
	// but no scope rule grants it access to any key.
	ErrCallerNotAuthorized = errors.New("keyservice: caller is not authorized to use this key service")

	// ErrKeyOutOfScope is returned when the caller is known but the
	// requested key is outside of the scope assigned to it.
	ErrKeyOutOfScope = errors.New("keyservice: requested key is outside of the caller's permitted scope")

	// ErrRateLimited is returned when the token bucket for the key service
	// is exhausted. The request is rejected immediately instead of queued.
	ErrRateLimited = errors.New("keyservice: rate limit exceeded")

	// ErrQueueFull is returned when the maximum number of queued requests
	// has been reached. The request is rejected immediately.
	ErrQueueFull = errors.New("keyservice: request queue is full")

	// ErrQueueTimeout is returned when a request waited in the queue longer
	// than the configured queue timeout without obtaining a worker slot.
	ErrQueueTimeout = errors.New("keyservice: timed out waiting for a free key service worker")

	// ErrBackendTimeout is returned when the key backend did not finish
	// within the configured request timeout. It is distinct from an
	// authentication or authorization rejection.
	ErrBackendTimeout = errors.New("keyservice: key backend operation timed out")

	// ErrLocalOnly is returned when the listener configuration would expose
	// an unauthenticated key service to the network.
	ErrLocalOnly = errors.New("keyservice: unauthenticated key service may only listen on a loopback or unix socket address")

	// ErrAnonymousNotLocal is returned when anonymous access is enabled for
	// a listener that is reachable from outside the local machine.
	ErrAnonymousNotLocal = errors.New("keyservice: anonymous access is only permitted on a loopback or unix socket address")

	// ErrPeerCertificateExpired is returned when a certificate used to
	// verify the peer is expired or not yet valid. The service never falls
	// back to unverified transport when this happens.
	ErrPeerCertificateExpired = errors.New("keyservice: peer certificate is expired or not yet valid")

	// ErrUntrustedPeer is returned when the peer certificate chain cannot be
	// verified against the configured trust anchors.
	ErrUntrustedPeer = errors.New("keyservice: peer certificate is not trusted")

	// ErrServerIdentityMismatch is returned when the server certificate does
	// not match the identity the client declared it expects.
	ErrServerIdentityMismatch = errors.New("keyservice: server identity does not match the expected identity")
)

// Sanitized audit reasons. These never contain key identifiers, ciphertext or
// plaintext.
const (
	auditOutcomeAllowed  = "allowed"
	auditOutcomeDenied   = "denied"
	auditOutcomeError    = "error"
	auditAllowedReason   = ""
	auditUnauthenticated = "unauthenticated"
	auditNotAuthorized   = "not_authorized"
	auditOutOfScope      = "out_of_scope"
	auditRateLimited     = "rate_limited"
	auditQueueFull       = "queue_full"
	auditQueueTimeout    = "queue_timeout"
	auditBackendTimeout  = "backend_timeout"
	auditBackendError    = "backend_error"
	auditPromptRejected  = "prompt_rejected"
	auditRemoteCanceled  = "canceled"
)

// reasonOf classifies an error into one of the fixed audit reason codes. The
// error text itself is deliberately not used, because backend errors can
// contain key identifiers.
func reasonOf(err error) string {
	switch {
	case err == nil:
		return auditAllowedReason
	case errors.Is(err, ErrAuthenticationRequired):
		return auditUnauthenticated
	case errors.Is(err, ErrCallerNotAuthorized):
		return auditNotAuthorized
	case errors.Is(err, ErrKeyOutOfScope):
		return auditOutOfScope
	case errors.Is(err, ErrRateLimited):
		return auditRateLimited
	case errors.Is(err, ErrQueueFull):
		return auditQueueFull
	case errors.Is(err, ErrQueueTimeout):
		return auditQueueTimeout
	case errors.Is(err, ErrBackendTimeout):
		return auditBackendTimeout
	default:
		return auditBackendError
	}
}

// reasonForHandshakeFailure maps a TLS verification error to a stable audit
// reason. It never includes certificate contents.
func reasonForHandshakeFailure(err error) string {
	switch {
	case errors.Is(err, ErrPeerCertificateExpired):
		return "peer_certificate_expired"
	case errors.Is(err, ErrServerIdentityMismatch):
		return "server_identity_mismatch"
	case errors.Is(err, ErrUntrustedPeer):
		return "untrusted_peer"
	case errors.Is(err, ErrAuthenticationRequired):
		return auditUnauthenticated
	default:
		return "handshake_failed"
	}
}
