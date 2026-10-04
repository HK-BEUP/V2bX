package beupguard

import (
	"testing"
)

func TestCancelUnacceptedIntentDoesNotReleaseOrReplay(t *testing.T) {
	f := controllerSetup(t)
	block := f.command(1, "block", f.l)
	f.advance(61)
	if _, err := f.c.Execute(block); err == nil {
		t.Fatal("expired block accepted")
	}
	cancel := f.command(1, "cancel", f.l)
	ack, err := f.c.Execute(cancel)
	if err != nil || ack.State != "not_applied" || ack.RejectNew || ack.ExistingClosed {
		t.Fatal(ack, err)
	}
	if _, err := f.c.Execute(block); err == nil {
		t.Fatal("cancelled sequence replay accepted")
	}
	f.restart(t)
	ack, err = f.c.Execute(cancel)
	if err != nil || ack.State != "not_applied" {
		t.Fatal("cancel did not persist", ack, err)
	}
	l := f.l
	l.ID = "00000000000000000000000000000002"
	l.StartedAt = f.now.Unix()
	l.ExpiresAt = l.StartedAt + 600
	if ack, err = f.c.Execute(f.command(2, "block", l)); err != nil || !ack.RejectNew {
		t.Fatal(ack, err)
	}
	if _, err = f.c.Execute(f.command(3, "cancel", l)); err == nil {
		t.Fatal("cancel cleared accepted isolation")
	}
	if ack, err = f.c.Execute(f.command(3, "release", l)); err != nil || ack.State != "ended" {
		t.Fatal(ack, err)
	}
}
