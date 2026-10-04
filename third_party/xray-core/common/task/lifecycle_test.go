package task

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observer struct {
	active   atomic.Int64
	blocked  atomic.Bool
	finished chan struct{}
}

func (o *observer) Begin() (func(), error) {
	if o.blocked.Load() {
		return nil, errors.New("fenced")
	}
	o.active.Add(1)
	var once sync.Once
	return func() { once.Do(func() { o.active.Add(-1); o.finished <- struct{}{} }) }, nil
}
func TestLifecycleSurvivesRunFirstError(t *testing.T) {
	o := &observer{finished: make(chan struct{}, 2)}
	ctx := WithLifecycle(context.Background(), o)
	late := make(chan struct{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, func() error { <-started; return errors.New("first fails") }, func() error { close(started); <-late; return nil })
	}()
	if e := <-done; e == nil {
		t.Fatal("expected early error")
	}
	<-o.finished
	if o.active.Load() != 1 {
		t.Fatal("late writer disappeared when Run returned")
	}
	close(late)
	select {
	case <-o.finished:
	case <-time.After(time.Second):
		t.Fatal("child did not finish")
	}
	if o.active.Load() != 0 {
		t.Fatal("child remains after completion")
	}
}
func TestLifecycleSurvivesContextCancellation(t *testing.T) {
	o := &observer{finished: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(WithLifecycle(context.Background(), o))
	late := make(chan struct{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Run(ctx, func() error { close(started); <-late; return nil }) }()
	<-started
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if o.active.Load() != 1 {
		t.Fatal("cancel erased still running child")
	}
	close(late)
	<-o.finished
	if o.active.Load() != 0 {
		t.Fatal("completion not observed")
	}
}
func TestLifecycleRefusesNewTaskAfterFence(t *testing.T) {
	o := &observer{finished: make(chan struct{}, 1)}
	o.blocked.Store(true)
	run := false
	e := Run(WithLifecycle(context.Background(), o), func() error { run = true; return nil })
	if e == nil || run || o.active.Load() != 0 {
		t.Fatal("fenced task ran")
	}
}
