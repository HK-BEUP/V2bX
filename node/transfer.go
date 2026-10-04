package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/beuptransfer"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	log "github.com/sirupsen/logrus"
)

type transferHost struct {
	legacy                                    bool
	legacyNext                                *panel.NodeInfo
	legacyUsers                               []panel.UserInfo
	closeMu                                   sync.Mutex
	store                                     *beuptransfer.FileStore
	box                                       *beuptransfer.Outbox
	session                                   *beuptransfer.CounterSession
	runtime                                   *beuptransfer.Runtime
	worker                                    *beuptransfer.Worker
	nodeAdded, finished                       bool
	scope, epoch                              string
	lastPull, lastOnline, lastSpeed, lastCert time.Time
	lastUsage                                 map[beuptransfer.Identity]beuptransfer.Sample
	lastReport                                time.Time
	configChanged                             bool
}
type transferStep struct{ c *Controller }

func (s transferStep) Step(ctx context.Context) error { return s.c.transferStep(ctx) }

func (c *Controller) startTransfer() (result error) {
	if c.transfer != nil {
		return errors.New("controller already started")
	}
	cfg := c.Options.TransferAccounting
	u, err := url.Parse(c.apiClient.APIHost)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || c.apiClient.NodeType != "vless" || c.apiClient.NodeId <= 0 {
		return errors.New("reliable accounting requires a bound HTTPS VLESS panel origin")
	}
	if err = c.apiClient.SetTrafficEpoch(cfg.Epoch); err != nil {
		return err
	}
	store, err := beuptransfer.OpenFileStore(cfg.Directory)
	if err != nil {
		return err
	}
	h := &transferHost{store: store, scope: fmt.Sprintf("vless-%d", c.apiClient.NodeId), epoch: cfg.Epoch, lastUsage: map[beuptransfer.Identity]beuptransfer.Sample{}}
	c.transfer = h
	defer func() {
		if result != nil {
			result = errors.Join(result, c.closeTransfer())
		}
	}()
	key, err := store.ReadKey()
	if err != nil {
		return err
	}
	defer clear(key)
	base := u.Scheme + "://" + u.Host + "/api/v1/accounts-node-settlement/" + h.scope
	receiver, err := beuptransfer.NewHTTPReceiver(base+"/traffic", h.scope, key)
	if err != nil {
		return err
	}
	control, err := beuptransfer.NewHTTPControl(base+"/control", base+"/probe", h.scope, key)
	if err != nil {
		return err
	}
	drain, err := beuptransfer.NewHTTPDrainReporter(base+"/drain", h.scope, key)
	if err != nil {
		return err
	}
	h.box, err = beuptransfer.Open(store, receiver, h.scope, h.epoch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Replay exact pending bytes before any process recovery; never drop an ack.
	// An unclean restart remains permanently ineligible for new migration proofs.
	if _, err = h.box.Replay(ctx); err != nil {
		return err
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
	users, err := c.apiClient.GetUserListContext(ctx)
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
	h.runtime, err = beuptransfer.NewRuntime(h.scope, h.epoch, h.box, h.session, transferControl{control, h}, drain)
	if err != nil {
		return err
	}
	if err = c.applyTransferUsers(users); err != nil {
		return err
	}
	// Establish signed accounting before publishing a running controller.
	// Migration control may legitimately remain blocked after an unclean exit;
	// the worker handles that separately without disabling ordinary service.
	totals, err := h.session.Snapshot(ctx)
	if err == nil {
		_, err = h.box.Flush(ctx, totals)
	}
	if err != nil {
		return err
	}
	h.lastPull = time.Now()
	h.lastCert = h.lastPull
	h.worker, err = beuptransfer.NewWorker(transferStep{c}, 5*time.Second, 45*time.Second)
	if err != nil {
		return err
	}
	if err = h.worker.Start(context.Background()); err != nil {
		return err
	}
	log.WithField("tag", c.tag).Info("Reliable accounting controller started")
	return nil
}

func (c *Controller) applyTransferUsers(users []panel.UserInfo) error {
	if users == nil {
		return nil
	}
	deleted, added := compareUserList(c.userList, users)
	// Apply one identity at a time; a later failure leaves an exact local list
	// for retry, rather than claiming an entire partially applied list succeeded.
	for _, user := range deleted {
		if err := c.server.DelUsers([]panel.UserInfo{user}, c.tag, c.info); err != nil {
			c.apiClient.ForgetUserList()
			return err
		}
		c.limiter.UpdateUser(c.tag, nil, []panel.UserInfo{user})
		remaining := c.userList[:0]
		for _, old := range c.userList {
			if old.Uuid != user.Uuid || old.Id != user.Id {
				remaining = append(remaining, old)
			}
		}
		c.userList = remaining
		delete(c.traffic, user.Uuid)
	}
	for _, user := range added {
		c.limiter.UpdateUser(c.tag, []panel.UserInfo{user}, nil)
		if _, err := c.server.AddUsers(&vCore.AddUsersParams{Tag: c.tag, NodeInfo: c.info, Users: []panel.UserInfo{user}}); err != nil {
			c.limiter.UpdateUser(c.tag, nil, []panel.UserInfo{user})
			c.apiClient.ForgetUserList()
			return err
		}
		c.userList = append(c.userList, user)
	}
	return nil
}

func (c *Controller) transferStep(ctx context.Context) error {
	h := c.transfer
	now := time.Now()
	var failures []error
	if now.Sub(h.lastPull) >= c.info.PullInterval {
		h.lastPull = now
		next, err := c.apiClient.GetNodeInfoContext(ctx)
		if err != nil {
			failures = append(failures, err)
		} else if next != nil && !reflect.DeepEqual(next, c.info) {
			h.configChanged = true
		}
		if h.configChanged {
			failures = append(failures, errors.New("node configuration changed; controlled accounting restart required"))
		}
		users, err := c.apiClient.GetUserListContext(ctx)
		if err != nil {
			failures = append(failures, err)
		} else if err = c.applyTransferUsers(users); err != nil {
			failures = append(failures, err)
		}
		alive, err := c.apiClient.GetUserAliveContext(ctx)
		if err != nil {
			failures = append(failures, err)
		} else {
			c.limiter.UpdateAliveList(alive)
		}
	}
	// List/config errors do not stop durable accounting of already admitted users.
	if err := h.runtime.Step(ctx); err != nil {
		failures = append(failures, err)
	}
	if now.Sub(h.lastOnline) >= c.info.PushInterval {
		h.lastOnline = now
		if err := c.reportTransferPresence(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if c.LimitConfig.EnableDynamicSpeedLimit && now.Sub(h.lastSpeed) >= time.Duration(c.LimitConfig.DynamicSpeedLimitConfig.Periodic)*time.Second {
		h.lastSpeed = now
		if err := c.SpeedChecker(); err != nil {
			failures = append(failures, err)
		}
	}
	if c.info.Security == panel.Tls && now.Sub(h.lastCert) >= 24*time.Hour {
		h.lastCert = now
		switch c.CertConfig.CertMode {
		case "", "none", "file", "self":
		default:
			if err := c.renewCertTask(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) > 0 {
		log.WithField("tag", c.tag).Warn("Reliable accounting cycle incomplete; retrying with journal retained")
	}
	return errors.Join(failures...)
}

func (c *Controller) reportTransferPresence(ctx context.Context) error {
	h := c.transfer
	rows, err := h.session.Snapshot(ctx)
	if err != nil {
		return err
	}
	totals := map[int]int64{}
	current := map[beuptransfer.Identity]beuptransfer.Sample{}
	for _, row := range rows {
		id := beuptransfer.Identity{UID: row.UID, Credential: row.Credential}
		old := h.lastUsage[id]
		if row.Upload < old.Upload || row.Download < old.Download {
			return beuptransfer.ErrEpoch
		}
		up, down := row.Upload-old.Upload, row.Download-old.Download
		if up > math.MaxInt64-down || totals[int(row.UID)] > math.MaxInt64-up-down {
			return beuptransfer.ErrCoverage
		}
		totals[int(row.UID)] += up + down
		current[id] = row
	}
	online, err := c.limiter.GetOnlineDevice()
	if err != nil {
		return err
	}
	data := map[int][]string{}
	for _, row := range *online {
		if totals[row.UID] >= c.Options.DeviceOnlineMinTraffic*1000 {
			data[row.UID] = append(data[row.UID], row.IP)
		}
	}
	if err = c.apiClient.ReportNodeOnlineUsersContext(ctx, &data); err != nil {
		return err
	}
	h.lastUsage = current
	if c.LimitConfig.EnableDynamicSpeedLimit {
		for _, u := range c.userList {
			if n := totals[u.Id]; n > 0 {
				if c.traffic[u.Uuid] > math.MaxInt64-n {
					c.traffic[u.Uuid] = math.MaxInt64
				} else {
					c.traffic[u.Uuid] += n
				}
			}
		}
	}
	return nil
}

func (c *Controller) closeTransfer() error {
	h := c.transfer
	if h == nil {
		return nil
	}
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	if h.finished {
		return nil
	}
	timeout := 60 * time.Second
	if h.legacy {
		timeout = 150 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if h.worker != nil {
		if err := h.worker.Close(ctx); err != nil {
			return err
		}
	}
	if h.session != nil {
		for {
			err := h.session.Seal(ctx)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return errors.Join(err, ctx.Err())
			}
			delay := 100 * time.Millisecond
			if h.legacy {
				delay = 2 * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	if h.nodeAdded {
		if err := c.server.DelNode(c.tag); err != nil {
			return err
		}
		h.nodeAdded = false
	}
	if c.limiter != nil {
		limiter.DeleteLimiter(c.tag)
	}
	if err := h.store.Close(); err != nil {
		return err
	}
	h.finished = true
	return nil
}

// A changed node configuration cannot earn a fresh pre-pause capability proof.
// Existing drain requests still execute so a paused transfer is not abandoned.
type transferControl struct {
	inner beuptransfer.RuntimeControl
	host  *transferHost
}

func (c transferControl) Poll(ctx context.Context, epoch string) ([]beuptransfer.Command, error) {
	commands, err := c.inner.Poll(ctx, epoch)
	if err != nil || !c.host.configChanged {
		return commands, err
	}
	result := make([]beuptransfer.Command, 0, len(commands))
	for _, cmd := range commands {
		if cmd.Kind != "probe" {
			result = append(result, cmd)
		}
	}
	return result, nil
}
func (c transferControl) Probe(ctx context.Context, cmd beuptransfer.Command, status beuptransfer.ProbeStatus) error {
	if c.host.configChanged {
		return beuptransfer.ErrCoverage
	}
	return c.inner.Probe(ctx, cmd, status)
}
