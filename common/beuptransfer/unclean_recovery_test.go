package beuptransfer

import (
	"errors"
	"strings"
	"testing"
)

func TestUncleanRecoveryResumesKnownBytesButNeverProvesMissingTail(t *testing.T) {
	o, store, receiver := setup(t)
	a, c := sessionAdapter(t)
	first, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	id := addSessionUser(t, a, c, 20, 30)
	rows, _ := first.Snapshot(ctx)
	receiver.lostResponse = true
	if _, err = o.Flush(ctx, rows); err == nil {
		t.Fatal("lost response did not remain pending")
	}
	// These bytes were only in process memory when it died; no code may claim
	// to know them from the journal or label recovery as complete settlement.
	c.put([]Sample{{id.UID, id.Credential, 27, 38}})
	o, err = Open(store, receiver, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	fresh, current := sessionAdapter(t)
	if _, err = o.ResumeUncleanCounterSession(ctx, strings.Repeat("3", 32), fresh); !errors.Is(err, ErrEpoch) {
		t.Fatal("unacknowledged batch bypassed", err)
	}
	if _, err = o.Replay(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = o.BeginCounterSession(ctx, strings.Repeat("3", 32), fresh); !errors.Is(err, ErrUnsealed) || !errors.Is(err, ErrEpoch) {
		t.Fatal("strict restart gate weakened", err)
	}
	resumed, err := o.ResumeUncleanCounterSession(ctx, strings.Repeat("3", 32), fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Uncertain() || o.state.Session.Recovery.Count != 1 || o.state.Session.Recovery.PreviousProcess != strings.Repeat("2", 32) {
		t.Fatal("missing recovery provenance")
	}
	addSessionUser(t, fresh, current, 5, 6)
	end, err := fresh.Track("one", func() {})
	if err != nil {
		t.Fatal("normal service did not resume", err)
	}
	end()
	rows, _ = resumed.Snapshot(ctx)
	if _, err = o.Flush(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if receiver.up != 25 || receiver.down != 36 {
		t.Fatal("known batch lost or billed twice", receiver.up, receiver.down)
	}
	quality, err := resumed.Inspect(ctx, id)
	if err != nil || quality.TrackingReady {
		t.Fatal("missing tail represented as complete", err)
	}
	request := DrainRequest{strings.Repeat("d", 32), id}
	if proof, err := o.Drain(ctx, request, resumed); err == nil || proof != nil {
		t.Fatal("new proof issued across unknown tail")
	}
	if err = resumed.Seal(ctx); err != nil {
		t.Fatal("local process could not seal", err)
	}
	o, err = Open(store, receiver, "vless_42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := sessionAdapter(t)
	last, err := o.BeginCounterSession(ctx, strings.Repeat("4", 32), again)
	if err != nil {
		t.Fatal(err)
	}
	quality, err = last.Inspect(ctx, id)
	if err != nil || quality.TrackingReady || !last.Uncertain() {
		t.Fatal("clean restart laundered uncertain history")
	}
}

func TestUncleanRecoveryCannotReplaceCleanOrSameProcess(t *testing.T) {
	o, _, _ := setup(t)
	a, _ := sessionAdapter(t)
	if _, err := o.ResumeUncleanCounterSession(ctx, strings.Repeat("2", 32), a); err == nil {
		t.Fatal("fresh stream entered recovery")
	}
	first, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := sessionAdapter(t)
	if _, err = o.ResumeUncleanCounterSession(ctx, strings.Repeat("2", 32), fresh); err == nil {
		t.Fatal("same process relabeled")
	}
	if err = first.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = o.ResumeUncleanCounterSession(ctx, strings.Repeat("3", 32), fresh); err == nil {
		t.Fatal("sealed stream entered abnormal recovery")
	}
}
