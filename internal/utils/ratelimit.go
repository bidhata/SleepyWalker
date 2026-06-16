package utils

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter provides adaptive rate limiting with backoff on server stress signals.
type RateLimiter struct {
	baseDelay   time.Duration
	currentDelay time.Duration
	maxRequests int64
	reqCount    atomic.Int64
	mu          sync.Mutex
	backoffUntil time.Time
}

// NewRateLimiter creates a rate limiter with the given base delay and max requests.
func NewRateLimiter(baseDelay time.Duration, maxRequests int) *RateLimiter {
	return &RateLimiter{
		baseDelay:    baseDelay,
		currentDelay: baseDelay,
		maxRequests:  int64(maxRequests),
	}
}

// Wait blocks until the rate limiter allows the next request.
// Returns false if the max request budget is exhausted.
func (rl *RateLimiter) Wait() bool {
	if rl.maxRequests > 0 && rl.reqCount.Load() >= rl.maxRequests {
		return false
	}

	rl.mu.Lock()
	delay := rl.currentDelay
	backoff := rl.backoffUntil
	rl.mu.Unlock()

	// If in backoff period, wait until it passes
	if !backoff.IsZero() && time.Now().Before(backoff) {
		waitDur := time.Until(backoff)
		log.Printf("[RATE] Backing off for %v", waitDur)
		time.Sleep(waitDur)
	}

	if delay > 0 {
		time.Sleep(delay)
	}

	rl.reqCount.Add(1)
	return true
}

// RecordResponse adapts the rate based on HTTP status codes.
func (rl *RateLimiter) RecordResponse(statusCode int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	switch {
	case statusCode == 429 || statusCode == 503:
		// Exponential backoff: double delay, set backoff window
		rl.currentDelay = rl.currentDelay*2 + 500*time.Millisecond
		if rl.currentDelay > 30*time.Second {
			rl.currentDelay = 30 * time.Second
		}
		rl.backoffUntil = time.Now().Add(rl.currentDelay)
		log.Printf("[RATE] Server stressed (HTTP %d) — increasing delay to %v", statusCode, rl.currentDelay)

	case statusCode >= 200 && statusCode < 400:
		// Gradually recover toward base delay
		if rl.currentDelay > rl.baseDelay {
			rl.currentDelay = rl.currentDelay * 3 / 4
			if rl.currentDelay < rl.baseDelay {
				rl.currentDelay = rl.baseDelay
			}
		}
	}
}

// RequestCount returns total requests made through this limiter.
func (rl *RateLimiter) RequestCount() int64 {
	return rl.reqCount.Load()
}

// BudgetExhausted returns true if max requests reached.
func (rl *RateLimiter) BudgetExhausted() bool {
	return rl.maxRequests > 0 && rl.reqCount.Load() >= rl.maxRequests
}
