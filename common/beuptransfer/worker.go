package beuptransfer

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Stepper interface{ Step(context.Context) error }

// Worker owns one sequential accounting loop. Transient failures retry; Close
// cancels and waits for the in-flight step. A Close timeout is not permission
// for the host to delete counters or close the outbox store.
type Worker struct {
	mu                sync.Mutex
	stepper           Stepper
	interval, timeout time.Duration
	cancel            context.CancelFunc
	done              chan struct{}
	status            WorkerStatus
}
type WorkerStatus struct {
	Started, Stopped                       bool
	Attempts, Successes, ConsecutiveErrors uint64
	LastSuccess                            time.Time
}

func NewWorker(s Stepper, interval, timeout time.Duration) (*Worker, error) {
	if s == nil || interval <= 0 || timeout <= 0 {
		return nil, errors.New("invalid accounting worker configuration")
	}
	return &Worker{stepper: s, interval: interval, timeout: timeout, done: make(chan struct{})}, nil
}
func (w *Worker) Status() WorkerStatus { w.mu.Lock(); defer w.mu.Unlock(); return w.status }
func (w *Worker) Start(parent context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if parent == nil || parent.Err() != nil || w.status.Started || w.status.Stopped {
		return errors.New("accounting worker cannot start")
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.status.Started = true
	go w.run(ctx)
	return nil
}
func (w *Worker) run(ctx context.Context) {
	defer func() { w.mu.Lock(); w.status.Stopped = true; close(w.done); w.mu.Unlock() }()
	for ctx.Err() == nil {
		stepCtx, cancel := context.WithTimeout(ctx, w.timeout)
		err := w.stepper.Step(stepCtx)
		// Returning nil after a deadline does not establish a successful cycle.
		if err == nil {
			err = stepCtx.Err()
		}
		cancel()
		w.mu.Lock()
		w.status.Attempts++
		if err == nil {
			w.status.Successes++
			w.status.LastSuccess = time.Now()
			w.status.ConsecutiveErrors = 0
		} else {
			w.status.ConsecutiveErrors++
		}
		w.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(w.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (w *Worker) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("close context required")
	}
	w.mu.Lock()
	if !w.status.Started && !w.status.Stopped {
		w.status.Stopped = true
		close(w.done)
	}
	if w.cancel != nil {
		w.cancel()
	}
	done := w.done
	w.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
