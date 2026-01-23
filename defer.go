package caddy_oidc

import (
	"context"
)

// DeferredResult represents a computation that runs in the background.
type DeferredResult[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// Defer starts the provided function in a separate goroutine and returns a handle to the result.
func Defer[T any](deferFunc func() (T, error)) *DeferredResult[T] {
	var deferred = &DeferredResult[T]{
		done: make(chan struct{}),
	}

	go func() {
		deferred.value, deferred.err = deferFunc()
		close(deferred.done)
	}()

	return deferred
}

// Get blocks until the background process is finished or the context is canceled.
//
//nolint:ireturn
func (d *DeferredResult[T]) Get(ctx context.Context) (T, error) {
	select {
	case <-ctx.Done():
		var zero T

		return zero, ctx.Err()
	case <-d.done:
		return d.value, d.err
	}
}
