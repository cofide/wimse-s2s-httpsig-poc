package backoff

import (
	"math"
	"sync"
	"time"
)

// Backoff is a simple exponential backoff implementation.
type Backoff struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	n            int

	mutex sync.Mutex
}

type BackoffOption func(*Backoff)

func WithInitialDelay(d time.Duration) BackoffOption {
	return func(b *Backoff) {
		b.InitialDelay = d
	}
}

func WithMaxDelay(d time.Duration) BackoffOption {
	return func(b *Backoff) {
		b.MaxDelay = d
	}
}

func NewBackoff(opts ...BackoffOption) *Backoff {
	b := &Backoff{
		InitialDelay: time.Millisecond * 200,
		MaxDelay:     10 * time.Second,
		n:            0,
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

// Duration returns the next wait period for the backoff. Not goroutine-safe.
func (b *Backoff) Duration() time.Duration {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	backoff := float64(b.n) + 1
	d := math.Pow(2, backoff) * float64(b.InitialDelay)
	if d > float64(b.MaxDelay) {
		d = float64(b.MaxDelay)
	}

	b.n++
	return time.Duration(d) * time.Second
}

// Reset resets the backoff's state.
func (b *Backoff) Reset() {
	b.n = 0
}
