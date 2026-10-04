package observer

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPreparationLeavesTelemetryLockAvailable(t *testing.T) {
	o, _ := sample(t)
	var calls int
	var firstUnlocked bool
	o.now = func() time.Time {
		calls++
		if calls == 1 && o.mu.TryLock() {
			firstUnlocked = true
			o.mu.Unlock()
		}
		return time.Unix(epoch, 0)
	}
	request(o)
	if !firstUnlocked || calls != 2 {
		t.Fatal("digest preparation still inside the hot lock")
	}
	if n, lost := total(snapshot(t, o, epoch+60)); n != 1 || lost != 0 {
		t.Fatal("single request accounting changed")
	}
}

func TestPreparedTargetRechecksMinuteAndIdentity(t *testing.T) {
	t.Run("minute", func(t *testing.T) {
		o, _ := sample(t)
		var calls int
		o.now = func() time.Time {
			calls++
			if calls == 1 {
				return time.Unix(epoch, 0)
			}
			return time.Unix(epoch+60, 0)
		}
		request(o)
		if o.next == nil {
			t.Fatal("clock crossed during preparation but wrong window used")
		}
		a := o.next.accounts[testSubject]
		if a == nil || a.targets[o.digest("target-1800000060", "tcp\x00example.test")] != 1 {
			t.Fatal("target fingerprint not rebuilt for actual window")
		}
		if n, lost := total(snapshot(t, o, epoch+60)); n != 0 || lost != 0 {
			t.Fatal("contaminated old minute")
		}
		if n, lost := total(snapshot(t, o, epoch+120)); n != 1 || lost != 0 {
			t.Fatal("lost next minute")
		}
	})
	t.Run("revocation", func(t *testing.T) {
		o, _ := sample(t)
		var calls int
		o.now = func() time.Time {
			calls++
			if calls == 1 {
				if !o.mu.TryLock() {
					t.Fatal("cannot revoke while preparation holds lock")
				}
				delete(o.bindings, o.labelKey("test-inbound", "PRIVATE-TEST-CREDENTIAL"))
				o.mu.Unlock()
			}
			return time.Unix(epoch, 0)
		}
		request(o)
		r := snapshot(t, o, epoch+60)[0]
		if len(r.Subjects) != 0 || r.Quality.UnmappedRequests != 1 {
			t.Fatal("revoked binding sampled from stale authorization")
		}
	})
}

func TestPreparedTargetClockJumpStillReportsLoss(t *testing.T) {
	o, _ := sample(t)
	var calls atomic.Int64
	o.now = func() time.Time {
		if calls.Add(1) == 1 {
			return time.Unix(epoch, 0)
		}
		return time.Unix(epoch+120, 0)
	}
	request(o)
	r := snapshot(t, o, epoch+180)[0]
	if len(r.Subjects) != 0 || !r.Quality.ClockDiscontinuity || !r.Quality.PartialWindow || r.Quality.DroppedRequests != 1 {
		t.Fatal("clock jump hidden by preparation")
	}
}
