package keyservice

import (
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// MetricsSnapshot is a point-in-time view of the key service concurrency and
// rejection counters. It is safe to log: it contains no key identifiers and
// no key material.
type MetricsSnapshot struct {
	Requests        uint64
	Allowed         uint64
	Denied          uint64
	Errors          uint64
	RateLimited     uint64
	QueueFull       uint64
	QueueTimeouts   uint64
	BackendTimeouts uint64
	Anonymous       uint64
	InFlight        int64
	Queued          int64
	Workers         int64
}

// Metrics holds the observable counters of a key service. The counters are
// exported so that an operator can scrape them from any in-process monitoring
// integration, and AuditLogger periodically writes them to the log.
type Metrics struct {
	requests        atomic.Uint64
	allowed         atomic.Uint64
	denied          atomic.Uint64
	errors          atomic.Uint64
	rateLimited     atomic.Uint64
	queueFull       atomic.Uint64
	queueTimeouts   atomic.Uint64
	backendTimeouts atomic.Uint64
	anonymous       atomic.Uint64
	inFlight        atomic.Int64
	queued          atomic.Int64
	workers         atomic.Int64
}

// Snapshot returns a consistent-enough view of the counters for logging.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		Requests:        m.requests.Load(),
		Allowed:         m.allowed.Load(),
		Denied:          m.denied.Load(),
		Errors:          m.errors.Load(),
		RateLimited:     m.rateLimited.Load(),
		QueueFull:       m.queueFull.Load(),
		QueueTimeouts:   m.queueTimeouts.Load(),
		BackendTimeouts: m.backendTimeouts.Load(),
		Anonymous:       m.anonymous.Load(),
		InFlight:        m.inFlight.Load(),
		Queued:          m.queued.Load(),
		Workers:         m.workers.Load(),
	}
}

// AuditEvent is one audit record of a key service request. All fields are
// non-secret: caller identity, operation class, key type (not identifier),
// outcome and reason.
type AuditEvent struct {
	Event     string // "keyservice.request"
	Caller    string // caller identity, e.g. CN or "anonymous"
	Operation string // "encrypt" or "decrypt"
	KeyType   string // e.g. "kms", "age"; empty when the request had no key
	Outcome   string // "allowed", "denied" or "error"
	Reason    string // sanitized reason code
	Peer      string // network peer, when known
	Duration  string
}

// AuditLogger writes audit records for every key service request decision.
// The caller identity and request class are always recorded; key identifiers,
// ciphertext, plaintext and decrypted data keys are never passed to it.
type AuditLogger struct {
	logger  *logrus.Logger
	metrics *Metrics
	mu      sync.Mutex
	last    MetricsSnapshot
}

// NewAuditLogger creates an AuditLogger backed by the given logrus logger.
func NewAuditLogger(logger *logrus.Logger, metrics *Metrics) *AuditLogger {
	return &AuditLogger{logger: logger, metrics: metrics}
}

// Log writes one audit record.
func (a *AuditLogger) Log(event AuditEvent) {
	if a == nil || a.logger == nil {
		return
	}
	a.logger.WithFields(logrus.Fields{
		"caller":    event.Caller,
		"operation": event.Operation,
		"key_type":  event.KeyType,
		"outcome":   event.Outcome,
		"reason":    event.Reason,
		"peer":      event.Peer,
		"duration":  event.Duration,
	}).Info(event.Event)
}

// LogHandshakeFailure records a rejected transport handshake. At that point no
// RPC exists yet, so there is no operation or key type; the peer address and a
// sanitized reason are the only facts available. This keeps failed
// authentication attempts auditable even though they never reach a handler.
func (a *AuditLogger) LogHandshakeFailure(peer, reason string) {
	if a == nil || a.logger == nil {
		return
	}
	if a.metrics != nil {
		a.metrics.denied.Add(1)
	}
	a.logger.WithFields(logrus.Fields{
		"caller":    "unknown",
		"operation": "handshake",
		"key_type":  "",
		"outcome":   auditOutcomeDenied,
		"reason":    reason,
		"peer":      peer,
		"duration":  "",
	}).Info("keyservice.request")
}

// LogMetrics writes a metrics snapshot. It is intended to be called
// periodically so that queue depth and rate limiting are observable.
func (a *AuditLogger) LogMetrics() {
	if a == nil || a.logger == nil || a.metrics == nil {
		return
	}
	s := a.metrics.Snapshot()
	a.mu.Lock()
	last := a.last
	a.last = s
	a.mu.Unlock()
	a.logger.WithFields(logrus.Fields{
		"requests":         s.Requests,
		"allowed":          s.Allowed,
		"denied":           s.Denied,
		"errors":           s.Errors,
		"rate_limited":     s.RateLimited,
		"queue_full":       s.QueueFull,
		"queue_timeouts":   s.QueueTimeouts,
		"backend_timeouts": s.BackendTimeouts,
		"anonymous":        s.Anonymous,
		"in_flight":        s.InFlight,
		"queued":           s.Queued,
		"workers":          s.Workers,
		"delta_requests":   s.Requests - last.Requests,
	}).Info("keyservice.metrics")
}
