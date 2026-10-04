package beuptransfer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type stepFunc func(context.Context) error

func (f stepFunc) Step(ctx context.Context) error { return f(ctx) }
func awaitStep(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("worker failed to progress")
	}
}

func TestWorkerRetriesErrorsThenClosesInflight(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	finished := make(chan struct{})
	w, _ := NewWorker(stepFunc(func(ctx context.Context) error {
		n := calls.Add(1)
		if n == 1 {
			return errors.New("transient failure")
		}
		if n == 2 {
			return nil
		}
		close(entered)
		<-ctx.Done()
		close(finished)
		return ctx.Err()
	}), time.Millisecond, time.Second)
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitStep(t, entered)
	if err := w.Start(context.Background()); err == nil {
		t.Fatal("started overlapping loop")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	awaitStep(t, finished)
	s := w.Status()
	if !s.Stopped || s.Attempts != 3 || s.Successes != 1 || s.LastSuccess.IsZero() {
		t.Fatal("wrong lifecycle evidence", s)
	}
	if err := w.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerDeadlineRetriesEvenIfStepReturnsNil(t *testing.T) {
	second := make(chan struct{})
	var calls atomic.Int32
	w, _ := NewWorker(stepFunc(func(ctx context.Context) error {
		if calls.Add(1) == 2 {
			close(second)
		}
		<-ctx.Done()
		return nil
	}), time.Millisecond, 5*time.Millisecond)
	_ = w.Start(context.Background())
	awaitStep(t, second)
	_ = w.Close(context.Background())
	if s := w.Status(); s.Successes != 0 || s.ConsecutiveErrors < 2 {
		t.Fatal("deadline treated as success", s)
	}
}

func TestWorkerCloseTimeoutDoesNotClaimStopped(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	w, _ := NewWorker(stepFunc(func(context.Context) error { close(entered); <-release; return nil }), time.Second, time.Second)
	_ = w.Start(context.Background())
	awaitStep(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(w.Close(ctx), context.Canceled) || w.Status().Stopped {
		t.Fatal("unfinished step reported stopped")
	}
	close(release)
	if err := w.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCancelDuringLongInterval(t *testing.T) {
	called := make(chan struct{})
	w, _ := NewWorker(stepFunc(func(context.Context) error { close(called); return nil }), time.Hour, time.Second)
	_ = w.Start(context.Background())
	awaitStep(t, called)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		t.Fatal("sleep prevented shutdown", err)
	}
}

func TestWorkerClosedBeforeStartAndInvalidConfig(t *testing.T) {
	if _, err := NewWorker(nil, time.Second, time.Second); err == nil {
		t.Fatal("nil stepper accepted")
	}
	w, _ := NewWorker(stepFunc(func(context.Context) error { t.Fatal("closed worker executed"); return nil }), time.Second, time.Second)
	if err := w.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err == nil {
		t.Fatal("closed worker restarted")
	}
}
