package beuptransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type asyncLegacyReceiver struct {
	seen map[uint64]bool
	receiver
}

func (r *asyncLegacyReceiver) Commit(ctx context.Context, b Batch) (Ack, error) {
	if r.seen == nil {
		r.seen = map[uint64]bool{}
	}
	if !r.seen[b.Sequence] {
		r.seen[b.Sequence] = true
		return Ack{}, ErrPending
	}
	return r.receiver.Commit(ctx, b)
}
func TestLegacyPayloadAndGeneration(t *testing.T) {
	store := &memoryStore{}
	r := &receiver{}
	o, epoch, err := OpenLegacy(store, r, "vless-42")
	if err != nil || !validHex(epoch, 16) {
		t.Fatal(err)
	}
	rows := []Sample{{7, strings.Repeat("a", 64), 10, 20}, {7, strings.Repeat("b", 64), 3, 4}, {8, strings.Repeat("c", 64), 0, 0}}
	if _, err = o.Flush(ctx, rows); err != nil {
		t.Fatal(err)
	}
	_, again, err := OpenLegacy(store, r, "vless-42")
	if err != nil || again != epoch {
		t.Fatal("local identity changed", err)
	}
	b := Batch{Version: 1, Scope: "vless-42", Epoch: epoch, Sequence: 1, Entries: rows}
	b.Digest = b.Hash()
	id, digest, data, err := LegacyPayload(b)
	if err != nil || len(data) != 1 || data[7] != [2]int64{13, 24} {
		t.Fatal("owner aggregation", data, err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("beup-legacy-report-v1\nvless-42\n%s\n7:13:24\n", id)))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatal("wire digest")
	}
	if _, _, err = OpenLegacy(store, r, "vless-43"); err == nil {
		t.Fatal("scope reused")
	}
	b.Entries[0].Upload = 1 << 53
	b.Digest = b.Hash()
	if _, _, _, err = LegacyPayload(b); err == nil {
		t.Fatal("overflow accepted")
	}
}
func TestLegacyAsyncSealTerminatesAndRestartsExactly(t *testing.T) {
	r := &asyncLegacyReceiver{}
	store := &memoryStore{}
	// Fixed local identity only simplifies the existing guard fixture.
	o, err := Open(store, r, "vless-42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	o.legacy = true
	a, c := sessionAdapter(t)
	s, err := o.BeginCounterSession(ctx, strings.Repeat("2", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	addSessionUser(t, a, c, 70, 80)
	if err = s.Seal(ctx); !errors.Is(err, ErrPending) || o.state.Session.Sealed {
		t.Fatal("accepted claimed settled", err)
	}
	if err = s.Seal(ctx); err != nil || !o.state.Session.Sealed || r.up != 70 || r.down != 80 || len(r.seen) != 1 {
		t.Fatal("async seal reissued a zero report", err, r.up, len(r.seen))
	}
	o, epoch, err := OpenLegacy(store, r, "vless-42")
	if err != nil || epoch != testEpoch {
		t.Fatal(err)
	}
	a, c = sessionAdapter(t)
	s, err = o.BeginCounterSession(ctx, strings.Repeat("3", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	addSessionUser(t, a, c, 10, 12)
	if err = s.Seal(ctx); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if err = s.Seal(ctx); err != nil || r.up != 80 || r.down != 92 {
		t.Fatal("restart tail duplicated", err, r.up, r.down)
	}
}

func TestLegacyThresholdAccumulatesAndSealKeepsSmallTail(t *testing.T) {
	r := &receiver{}
	store := &memoryStore{}
	o, err := Open(store, r, "vless-42", testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	o.legacy = true
	a, c := sessionAdapter(t)
	s, err := o.BeginCounterSession(ctx, strings.Repeat("4", 32), a)
	if err != nil {
		t.Fatal(err)
	}
	id := addSessionUser(t, a, c, 10, 15)
	rows, _ := s.Snapshot(ctx)
	if _, err = o.FlushLegacy(ctx, rows, 30); err != nil || r.up != 0 || r.down != 0 {
		t.Fatal("threshold ignored", err)
	}
	c.put([]Sample{{id.UID, id.Credential, 20, 25}})
	rows, _ = s.Snapshot(ctx)
	if _, err = o.FlushLegacy(ctx, rows, 30); err != nil || r.up != 20 || r.down != 25 {
		t.Fatal("small traffic did not accumulate", err)
	}
	c.put([]Sample{{id.UID, id.Credential, 22, 29}})
	rows, _ = s.Snapshot(ctx)
	if _, err = o.FlushLegacy(ctx, rows, 30); err != nil || r.up != 20 || r.down != 25 {
		t.Fatal("threshold reset", err)
	}
	if err = s.Seal(ctx); err != nil || r.up != 22 || r.down != 29 {
		t.Fatal("small final tail lost", err)
	}
}
