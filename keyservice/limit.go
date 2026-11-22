package keyservice

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Limiter bounds the number of key service requests that run concurrently and
// the rate at which they are admitted. Requests beyond the concurrency limit
// wait in a bounded queue instead of piling up goroutines, and every request
// carries its own queue and queue-wait deadline.
type Limiter struct {
	slots        chan struct{}
	limiter      *rate.Limiter
	queueTimeout time.Duration
	maxQueue     int
	metrics      *Metrics
	queued       atomic.Int64
}

// NewLimiter creates a limiter with maxConcurrent worker slots. A
// requestsPerSecond of zero or less disables rate limiting. queueWait is the
// maximum time a request may wait for a free slot.
func NewLimiter(maxConcurrent int, requestsPerSecond float64, burst int, queueWait time.Duration, maxQueue int, metrics *Metrics) *Limiter {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	l := &Limiter{
		slots:        make(chan struct{}, maxConcurrent),
		queueTimeout: queueWait,
		maxQueue:     maxQueue,
		metrics:      metrics,
	}
	if metrics != nil {
		metrics.workers.Store(int64(maxConcurrent))
	}
	if requestsPerSecond > 0 {
		if burst < 1 {
			burst = 1
		}
		l.limiter = rate.NewLimiter(rate.Limit(requestsPerSecond), burst)
	}
	return l
}

// Acquire admits one request. It returns nil when a slot was obtained and the
// caller must call Release exactly once. On rejection it returns ErrRateLimited,
// ErrQueueFull or ErrQueueTimeout, and never blocks longer than the queue wait.
func (l *Limiter) Acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if l.limiter != nil && !l.limiter.Allow() {
		if l.metrics != nil {
			l.metrics.rateLimited.Add(1)
		}
		return ErrRateLimited
	}

	// Fast path: a free slot without queueing.
	select {
	case l.slots <- struct{}{}:
		return nil
	default:
	}

	if l.maxQueue > 0 && l.queued.Load() >= int64(l.maxQueue) {
		if l.metrics != nil {
			l.metrics.queueFull.Add(1)
		}
		return ErrQueueFull
	}
	if l.metrics != nil {
		l.metrics.queued.Add(1)
	}
	l.queued.Add(1)
	defer func() {
		l.queued.Add(-1)
		if l.metrics != nil {
			l.metrics.queued.Add(-1)
		}
	}()

	timer := time.NewTimer(l.queueTimeout)
	defer timer.Stop()
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-timer.C:
		if l.metrics != nil {
			l.metrics.queueTimeouts.Add(1)
		}
		return ErrQueueTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a previously acquired slot.
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.slots:
	default:
	}
}

// Queued returns the number of requests currently waiting for a slot.
func (l *Limiter) Queued() int64 {
	if l == nil {
		return 0
	}
	return l.queued.Load()
}
