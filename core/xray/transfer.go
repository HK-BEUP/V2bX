package xray

import (
	"context"
	"fmt"
	"strings"

	"github.com/InazumaV/V2bX/common/beupguard"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/common/counter"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/core/xray/app/dispatcher"
	"github.com/xtls/xray-core/common/session"
)

type transferState struct {
	detach     func()
	adapter    *beuptransfer.GuardAdapter
	identities map[string]beuptransfer.Identity // protected by users.mapLock
}

// EnableTransferAccounting is an opt-in capability; the production controller
// does not call it yet. The receiver/cutover/runtime must be accepted first.
// Enable after AddNode and before AddUsers, never on a running credential set.
func (c *Xray) EnableTransferAccounting(tag, epoch, nodeType string) (*beuptransfer.GuardAdapter, error) {
	if nodeType != "vless" || tag == "" {
		return nil, beuptransfer.ErrCoverage
	}
	c.users.mapLock.Lock()
	defer c.users.mapLock.Unlock()
	if c.dispatcher == nil {
		return nil, beuptransfer.ErrCoverage
	}
	if _, ok := c.nodeReportMinTrafficBytes[tag]; !ok {
		return nil, fmt.Errorf("inbound not provisioned")
	}
	for label := range c.users.uidMap {
		if strings.HasPrefix(label, format.UserTag(tag, "")) {
			return nil, fmt.Errorf("live accounting cutover refused")
		}
	}
	if _, ok := c.transfers.Load(tag); ok {
		return nil, fmt.Errorf("transfer accounting already enabled")
	}
	a, err := beuptransfer.NewGuardAdapter(tag, epoch, func(context.Context) ([]beuptransfer.Sample, error) { return c.transferSnapshot(tag) })
	if err != nil {
		return nil, err
	}
	if err = beuptransfer.Install(tag, a); err != nil {
		return nil, err
	}
	detach, err := session.InstallCredentialTracker(tag, dispatcher.NewTransferCredentialTracker(a))
	if err != nil {
		beuptransfer.Remove(tag, a)
		return nil, err
	}
	c.dispatcher.Counter.LoadOrStore(tag, counter.NewTrafficCounter())
	c.transfers.Store(tag, &transferState{detach, a, map[string]beuptransfer.Identity{}})
	return a, nil
}

// Caller holds users.mapLock. Binding and zero counters exist before auth can
// succeed, so even a zero-byte final barrier has an explicit identity.
func (c *Xray) bindTransfer(tag, label string, uid int, credential string) error {
	v, enabled := c.transfers.Load(tag)
	if !enabled {
		return nil
	}
	s := v.(*transferState)
	if err := s.adapter.Bind(label, uid, credential); err != nil {
		return err
	}
	s.identities[label] = beuptransfer.Identity{UID: int64(uid), Credential: beupguard.CredentialDigest(credential)}
	value, _ := c.dispatcher.Counter.LoadOrStore(tag, counter.NewTrafficCounter())
	value.(*counter.TrafficCounter).GetCounter(label)
	return nil
}

func (c *Xray) transferSnapshot(tag string) ([]beuptransfer.Sample, error) {
	c.users.mapLock.RLock()
	defer c.users.mapLock.RUnlock()
	v, ok := c.transfers.Load(tag)
	if !ok || c.dispatcher == nil {
		return nil, beuptransfer.ErrCoverage
	}
	s := v.(*transferState)
	value, ok := c.dispatcher.Counter.Load(tag)
	if !ok {
		s.adapter.NoteCoverageFailure()
		return nil, beuptransfer.ErrCoverage
	}
	tc := value.(*counter.TrafficCounter)
	rows := make([]beuptransfer.Sample, 0, len(s.identities))
	for label, id := range s.identities {
		value, ok := tc.Counters.Load(label)
		if !ok {
			s.adapter.NoteCoverageFailure()
			return nil, beuptransfer.ErrCoverage
		}
		ts := value.(*counter.TrafficStorage)
		rows = append(rows, beuptransfer.Sample{UID: id.UID, Credential: id.Credential, Upload: ts.UpCounter.Load(), Download: ts.DownCounter.Load()})
	}
	return rows, nil
}
func (c *Xray) invalidateTransfer(tag string) {
	if v, ok := c.transfers.Load(tag); ok {
		beuptransfer.Remove(tag, v.(*transferState).adapter)
		v.(*transferState).detach()
	}
}

// Controller has joined its worker and durably sealed counters before DelNode.
// Retained identities are process-local; the next session restores the durable
// cumulative base, so keeping these counters would double count or deny startup.
func (c *Xray) purgeTransfer(tag string) {
	c.users.mapLock.Lock()
	defer c.users.mapLock.Unlock()
	for label := range c.users.uidMap {
		if strings.HasPrefix(label, format.UserTag(tag, "")) {
			delete(c.users.uidMap, label)
			c.dispatcher.LinkManagers.Delete(label)
		}
	}
	c.dispatcher.Counter.Delete(tag)
	c.transfers.Delete(tag)
	delete(c.nodeReportMinTrafficBytes, tag)
}
