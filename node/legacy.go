package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	"github.com/InazumaV/V2bX/limiter"
	log "github.com/sirupsen/logrus"
	"math"
	"net/url"
	"reflect"
	"time"
)

type legacyStep struct{ c *Controller }

func (s legacyStep) Step(ctx context.Context) error { return s.c.legacyStep(ctx) }
func legacyWait(ctx context.Context) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Controller) startLegacy() (result error) {
	if c.transfer != nil {
		return errors.New("controller already started")
	}
	cfg := c.Options.LegacyAccounting
	if c.Options.ReportMinTraffic < 0 || c.Options.ReportMinTraffic > math.MaxInt64/1024 {
		return errors.New("invalid legacy report threshold")
	}
	u, err := url.Parse(c.apiClient.APIHost)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || c.apiClient.NodeType != "vless" || c.apiClient.NodeId <= 0 {
		return errors.New("reliable accounting requires a bound HTTPS VLESS panel origin")
	}
	if err = c.apiClient.EnableLegacyAccounting(); err != nil {
		return err
	}
	store, err := beuptransfer.OpenFileStore(cfg.Directory)
	if err != nil {
		return err
	}
	h := &transferHost{store: store, scope: fmt.Sprintf("vless-%d", c.apiClient.NodeId), legacy: true, lastUsage: map[beuptransfer.Identity]beuptransfer.Sample{}}
	c.transfer = h
	defer func() {
		if result != nil {
			result = errors.Join(result, c.closeTransfer())
		}
	}()
	h.box, h.epoch, err = beuptransfer.OpenLegacy(store, c.apiClient, h.scope)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	// Replay exact pending bytes before any process recovery; never drop an ack.
	// An unclean restart remains permanently ineligible for new migration proofs.
	for {
		_, err = h.box.Replay(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, beuptransfer.ErrPending) {
			return err
		}
		if err = legacyWait(ctx); err != nil {
			return err
		}
	}
	node, err := c.apiClient.GetNodeInfoContext(ctx)
	if err != nil {
		return err
	}
	if node == nil {
		return errors.New("initial node configuration missing")
	}
	if node.Type != "vless" || node.Id != c.apiClient.NodeId || node.PullInterval <= 0 || node.PushInterval <= 0 {
		return errors.New("node scope or intervals changed")
	}
	users, err := c.initialLegacyUsers(ctx)
	if err != nil {
		return err
	}
	if users == nil {
		return errors.New("initial authoritative user list required")
	}
	alive, err := c.apiClient.GetUserAliveContext(ctx)
	if err != nil {
		return err
	}
	c.tag = c.Options.Name
	if c.tag == "" {
		c.tag = c.buildNodeTag(node)
	}
	c.info = node
	c.aliveMap = alive
	c.traffic = map[string]int64{}
	c.limiter = limiter.AddLimiter(c.tag, &c.LimitConfig, nil, alive)
	if err = c.limiter.UpdateRule(&node.Rules); err != nil {
		return err
	}
	if node.Security == panel.Tls {
		if err = c.requestCert(); err != nil {
			return err
		}
	}
	if err = c.server.AddNode(c.tag, node, c.Options); err != nil {
		return err
	}
	h.nodeAdded = true
	capable, ok := c.server.(interface {
		EnableTransferAccounting(string, string, string) (*beuptransfer.GuardAdapter, error)
	})
	if !ok {
		return beuptransfer.ErrCoverage
	}
	adapter, err := capable.EnableTransferAccounting(c.tag, h.epoch, node.Type)
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	h.session, err = h.box.BeginCounterSession(ctx, hex.EncodeToString(nonce), adapter)
	if errors.Is(err, beuptransfer.ErrUnsealed) {
		h.session, err = h.box.ResumeUncleanCounterSession(ctx, hex.EncodeToString(nonce), adapter)
	}
	if err != nil {
		return err
	}
	if h.session.Uncertain() {
		log.WithField("scope", h.scope).Error("Unclean counter history retained: normal service resumes known usage; migration proofs blocked pending reconciliation")
	}
	if err = c.applyTransferUsers(users); err != nil {
		return err
	}
	// Persist the first report and verify the old endpoint accepts it.
	// HTTP 202 keeps the journal pending until the scheduled SQL settlement.
	totals, err := h.session.Snapshot(ctx)
	if err == nil {
		_, err = h.box.FlushLegacy(ctx, totals, c.Options.ReportMinTraffic*1024)
	}
	if err != nil && !errors.Is(err, beuptransfer.ErrPending) {
		return err
	}
	h.lastPull = time.Now()
	h.lastReport = h.lastPull
	h.lastCert = h.lastPull
	h.worker, err = beuptransfer.NewWorker(legacyStep{c}, 5*time.Second, 45*time.Second)
	if err != nil {
		return err
	}
	if err = h.worker.Start(context.Background()); err != nil {
		return err
	}
	log.WithField("tag", c.tag).Info("Legacy Horizon accounting controller started")
	return nil
}

// The normal old panel pull, presence, speed and certificate tasks share one
// sequential loop with the outbox, so removal never races a counter reset.
func (c *Controller) legacyStep(ctx context.Context) error {
	h := c.transfer
	now := time.Now()
	var failures []error
	if now.Sub(h.lastPull) >= c.info.PullInterval {
		h.lastPull = now
		next, err := c.apiClient.GetNodeInfoContext(ctx)
		if err != nil {
			failures = append(failures, err)
		}
		users, err := c.apiClient.GetUserListContext(ctx)
		if err != nil {
			failures = append(failures, err)
		}
		if next != nil && !reflect.DeepEqual(next, c.info) {
			h.legacyNext = next
			if users == nil {
				users = append([]panel.UserInfo{}, c.userList...)
			}
		}
		if h.legacyNext != nil {
			if users != nil {
				h.legacyUsers = users
			}
		} else if err == nil {
			if e := c.applyTransferUsers(users); e != nil {
				failures = append(failures, e)
			}
		}
		alive, e := c.apiClient.GetUserAliveContext(ctx)
		if e != nil {
			failures = append(failures, e)
		} else {
			c.aliveMap = alive
			c.limiter.UpdateAliveList(alive)
		}
	}
	if h.legacyNext != nil {
		return c.reloadLegacy(ctx)
	}
	_, err := h.box.Replay(ctx)
	if err == nil && now.Sub(h.lastReport) >= c.info.PushInterval {
		var totals []beuptransfer.Sample
		totals, err = h.session.Snapshot(ctx)
		if err == nil {
			_, err = h.box.FlushLegacy(ctx, totals, c.Options.ReportMinTraffic*1024)
			h.lastReport = now
		}
	}
	if err != nil && !errors.Is(err, beuptransfer.ErrPending) {
		failures = append(failures, err)
	}
	if now.Sub(h.lastOnline) >= c.info.PushInterval {
		h.lastOnline = now
		if e := c.reportTransferPresence(ctx); e != nil {
			failures = append(failures, e)
		}
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && now.Sub(h.lastSpeed) >= time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.Periodic)*time.Second {
		h.lastSpeed = now
		if e := c.SpeedChecker(); e != nil {
			failures = append(failures, e)
		}
	}
	if c.info.Security == panel.Tls && now.Sub(h.lastCert) >= 24*time.Hour {
		h.lastCert = now
		switch c.CertConfig.CertMode {
		case "", "none", "file", "self":
		default:
			if e := c.renewCertTask(); e != nil {
				failures = append(failures, e)
			}
		}
	}
	if len(failures) > 0 {
		log.WithField("tag", c.tag).Warn("Legacy report or panel update pending; journal retained")
	}
	return errors.Join(failures...)
}

// Apply panel configuration changes only after the previous inbound's final
// counters have committed. On failure the exact next configuration is retained.
func (c *Controller) reloadLegacy(ctx context.Context) error {
	h := c.transfer
	next := h.legacyNext
	if next == nil {
		return nil
	}
	if next.Type != "vless" || next.Id != c.apiClient.NodeId || next.PullInterval <= 0 || next.PushInterval <= 0 {
		return errors.New("legacy configuration scope mismatch")
	}
	if h.session != nil {
		if err := h.session.Seal(ctx); err != nil {
			return err
		}
	}
	if h.nodeAdded {
		if err := c.server.DelNode(c.tag); err != nil {
			return err
		}
		h.nodeAdded = false
		limiter.DeleteLimiter(c.tag)
	}
	c.userList = nil
	c.tag = c.Options.Name
	if c.tag == "" {
		c.tag = c.buildNodeTag(next)
	}
	c.info = next
	c.limiter = limiter.AddLimiter(c.tag, &c.LimitConfig, nil, c.aliveMap)
	if err := c.limiter.UpdateRule(&next.Rules); err != nil {
		return err
	}
	if next.Security == panel.Tls {
		if err := c.requestCert(); err != nil {
			return err
		}
	}
	if err := c.server.AddNode(c.tag, next, c.Options); err != nil {
		return err
	}
	h.nodeAdded = true
	capable, ok := c.server.(interface {
		EnableTransferAccounting(string, string, string) (*beuptransfer.GuardAdapter, error)
	})
	if !ok {
		return beuptransfer.ErrCoverage
	}
	adapter, err := capable.EnableTransferAccounting(c.tag, h.epoch, next.Type)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	h.session, err = h.box.BeginCounterSession(ctx, hex.EncodeToString(nonce[:]), adapter)
	if err != nil {
		return err
	}
	if err = c.applyTransferUsers(h.legacyUsers); err != nil {
		return err
	}
	h.legacyNext = nil
	h.legacyUsers = nil
	h.lastUsage = map[beuptransfer.Identity]beuptransfer.Sample{}
	return nil
}

// Startup already owns a 150-second deadline. A lock-busy admission response
// keeps startup pending; no inbound/users are installed before a valid list.
func (c *Controller) initialLegacyUsers(ctx context.Context) ([]panel.UserInfo, error) {
 for {
  users, err := c.apiClient.GetUserListContext(ctx)
  if !errors.Is(err, panel.ErrLegacySettlementBusy) { return users, err }
  if err = legacyWait(ctx); err != nil { return nil, err }
 }
}
