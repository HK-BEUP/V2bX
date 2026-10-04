package beupguard

import (
	"sync"
	"sync/atomic"
)

type scopedGuard struct {
	guard *Guard
	tags  map[string]bool // Immutable after publication; nil is the legacy primary.
}
type guardGroup struct {
	primary *Guard
	entries []scopedGuard
}

var active atomic.Pointer[guardGroup]

// Set is the single-runtime compatibility entry point. Publish before loading users.
func Set(g *Guard) {
	if g == nil {
		active.Store(nil)
		return
	}
	active.Store(&guardGroup{primary: g, entries: []scopedGuard{{guard: g}}})
}
func Current() *Guard {
	if group := active.Load(); group != nil {
		return group.primary
	}
	return nil
}
func Enabled() bool { return active.Load() != nil }
func guardsForTag(tag string) []*Guard {
	group := active.Load()
	if group == nil {
		return nil
	}
	out := make([]*Guard, 0, len(group.entries))
	for _, entry := range group.entries {
		if entry.tags == nil || entry.tags[tag] {
			out = append(out, entry.guard)
		}
	}
	return out
}
func Bind(tag, label string, uid int, credential string) {
	for _, g := range guardsForTag(tag) {
		g.Bind(tag, label, uid, credential)
	}
}
func Unbind(tag, label string) {
	for _, g := range guardsForTag(tag) {
		g.Unbind(tag, label)
	}
}
func UnbindTag(tag string) {
	for _, g := range guardsForTag(tag) {
		g.mu.Lock()
		for b := range g.bindings {
			if b.Tag == tag {
				delete(g.bindings, b)
				delete(g.authorizations, b)
			}
		}
		g.mu.Unlock()
	}
}
func ResetBindings() {
	if group := active.Load(); group != nil {
		for _, entry := range group.entries {
			g := entry.guard
			g.mu.Lock()
			g.bindings = map[Binding]Identity{}
			g.authorizations = map[Binding]string{}
			g.authorizationUse = map[Identity]int64{}
			g.mu.Unlock()
		}
	}
}

// Every matching controller must see the session. A hold in either namespace
// wins, and releasing one controller never releases the other controller's hold.
func Track(tag, label string, close func()) (func(), error) {
	var closeOnce, finishOnce sync.Once
	closeFlow := func() {
		closeOnce.Do(func() {
			if close != nil {
				close()
			}
		})
	}
	var finishes []func()
	finish := func() {
		finishOnce.Do(func() {
			for _, f := range finishes {
				f()
			}
		})
	}
	lastError := ErrIdentity
	for _, g := range guardsForTag(tag) {
		f, err := g.Track(tag, label, closeFlow)
		if err == ErrIsolated {
			finish()
			return func() {}, err
		}
		if err != nil {
			lastError = err
			continue
		}
		finishes = append(finishes, f)
	}
	if len(finishes) == 0 {
		return finish, lastError
	}
	return finish, nil
}
func NoteCoverageFailure(tag string) {
	for _, g := range guardsForTag(tag) {
		g.NoteCoverageFailure()
	}
}
