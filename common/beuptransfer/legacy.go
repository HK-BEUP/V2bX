package beuptransfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// OpenLegacy reuses the durable outbox with a locally generated identity.
// No panel epoch registration, signing key, or control/probe endpoint is needed.
func OpenLegacy(store Store, receiver Receiver, scope string) (*Outbox, string, error) {
	raw, err := store.Load()
	if err != nil {
		return nil, "", err
	}
	var epoch string
	if len(raw) == 0 {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, "", err
		}
		epoch = hex.EncodeToString(id[:])
	} else {
		var header struct {
			Epoch string `json:"epoch"`
		}
		if err = json.Unmarshal(raw, &header); err != nil {
			return nil, "", err
		}
		epoch = header.Epoch
	}
	box, err := Open(store, receiver, scope, epoch)
	if err == nil {
		box.legacy = true
	}
	return box, epoch, err
}

// Called with the outbox lock held, after the inbound has quiesced. An async
// queue ACK for exactly these final totals is enough; issuing another empty
// report on every retry would keep a shutdown waiting forever.
func (o *Outbox) flushLegacySeal(ctx context.Context, rows []Sample) error {
	if _, err := o.replay(ctx); err != nil {
		return err
	}
	same := o.state.LastAck != nil && len(rows) == len(o.state.Committed)
	for i := range rows {
		if !same || rows[i] != o.state.Committed[i] {
			same = false
			break
		}
	}
	if same {
		return nil
	}
	_, err := o.flush(ctx, rows)
	return err
}

// Preserve the old per-credential report threshold during normal reporting.
// Small deltas remain in cumulative counters; Seal always flushes the full tail.
func (o *Outbox) FlushLegacy(ctx context.Context, totals []Sample, threshold int64) (*Ack, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.legacy || threshold < 0 {
		return nil, errors.New("invalid legacy report threshold")
	}
	if _, err := o.replay(ctx); err != nil {
		return nil, err
	}
	after, err := samples(totals)
	if err != nil {
		return nil, err
	}
	changes, err := delta(o.state.Committed, after)
	if err != nil {
		return nil, err
	}
	before := make(map[string]Sample, len(o.state.Committed))
	for _, row := range o.state.Committed {
		before[key(row)] = row
	}
	for i, change := range changes {
		if change.Upload <= threshold && change.Download <= threshold-change.Upload {
			prior := before[key(change)]
			after[i].Upload, after[i].Download = prior.Upload, prior.Download
		}
	}
	return o.flush(ctx, after)
}

// LegacyPayload aggregates credentials by owner exactly as the old push API does.
// Zero delta identities stay in the local journal but are not counted as online users.
func LegacyPayload(b Batch) (string, string, map[int64][2]int64, error) {
	if !scopePattern.MatchString(b.Scope) || !validHex(b.Epoch, 16) || b.Sequence < 1 || b.Sequence > 1<<53 || b.Version != 1 || b.Digest != b.Hash() {
		return "", "", nil, errors.New("invalid legacy batch")
	}
	rows, err := samples(b.Entries)
	if err != nil {
		return "", "", nil, err
	}
	data := make(map[int64][2]int64)
	for _, s := range rows {
		if s.Upload == 0 && s.Download == 0 {
			continue
		}
		sum := data[s.UID]
		if s.Upload > (1<<53)-sum[0] || s.Download > (1<<53)-sum[1] {
			return "", "", nil, errors.New("legacy traffic overflow")
		}
		data[s.UID] = [2]int64{sum[0] + s.Upload, sum[1] + s.Download}
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("beup-legacy-request-v1\n%s\n%s\n%d\n", b.Scope, b.Epoch, b.Sequence)))
	id := hex.EncodeToString(h[:16])
	wire := sha256.New()
	fmt.Fprintf(wire, "beup-legacy-report-v1\n%s\n%s\n", b.Scope, id)
	ids := make([]int64, 0, len(data))
	for uid := range data {
		ids = append(ids, uid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, uid := range ids {
		v := data[uid]
		fmt.Fprintf(wire, "%d:%d:%d\n", uid, v[0], v[1])
	}
	return id, hex.EncodeToString(wire.Sum(nil)), data, nil
}
