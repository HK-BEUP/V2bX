package conf

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchCandidate owns its goroutine and passes immutable parsed candidates to
// the host. It never overwrites the running Conf while controllers are sealing.
func WatchCandidate(file, xdns, sdns string, reload func(*Conf) error) (func(), error) {
	return watchCandidate(file, xdns, sdns, 5*time.Second, reload)
}

func watchCandidate(file, xdns, sdns string, delay time.Duration, reload func(*Conf) error) (func(), error) {
	if reload == nil || delay <= 0 {
		return nil, errors.New("configuration callback and delay required")
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	paths, dirs := map[string]bool{}, map[string]bool{}
	for _, path := range []string{file, xdns, sdns} {
		if path == "" {
			continue
		}
		abs, e := filepath.Abs(path)
		if e != nil {
			w.Close()
			return nil, e
		}
		paths[abs] = true
		dirs[filepath.Dir(abs)] = true
	}
	// Directory watches survive atomic configuration replacement.
	for dir := range dirs {
		if err = w.Add(dir); err != nil {
			w.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer w.Close()
		timer := time.NewTimer(delay)
		timer.Stop()
		defer timer.Stop()
		var tick <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				if !paths[filepath.Clean(event.Name)] || event.Op&^fsnotify.Chmod == 0 {
					continue
				}
				timer.Reset(delay)
				tick = timer.C
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Print("Configuration watch failed; active configuration retained")
			case <-tick:
				tick = nil
				if ctx.Err() != nil {
					return
				}
				next := New()
				if err := next.LoadFromPath(file); err != nil || len(next.CoresConfig) == 0 || len(next.NodeConfig) == 0 {
					// Decoder errors can quote credential-bearing source text.
					log.Print("Configuration candidate rejected; active configuration retained")
					continue
				}
				if ctx.Err() != nil {
					return
				}
				// Single worker: a second event cannot mutate or overtake this candidate.
				if err := reload(next); err != nil {
					log.Print("Configuration reload incomplete; inspect node accounting status")
				} else {
					log.Print("Configuration reload completed")
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(cancel); <-done }, nil
}

// A reload may change normal node settings, but cannot silently replace a
// durable billing generation or fall back to the legacy reset reporter.
func ValidateTransferReload(current, next *Conf) error {
	if current == nil || next == nil {
		return errors.New("configuration missing")
	}
	for _, old := range current.NodeConfig {
		if old.Options.TransferAccounting == nil && old.Options.LegacyAccounting == nil {
			continue
		}
		found := false
		for _, fresh := range next.NodeConfig {
			if old.ApiConfig.APIHost != fresh.ApiConfig.APIHost || old.ApiConfig.NodeType != fresh.ApiConfig.NodeType || old.ApiConfig.NodeID != fresh.ApiConfig.NodeID {
				continue
			}
			if found {
				return errors.New("duplicate reliable accounting scope")
			}
			found = true
			if old.Options.TransferAccounting != nil && (fresh.Options.TransferAccounting == nil || *old.Options.TransferAccounting != *fresh.Options.TransferAccounting || fresh.Options.LegacyAccounting != nil) {
				return errors.New("reliable accounting generation change requires reconciled rollout")
			}
			if old.Options.LegacyAccounting != nil && (fresh.Options.LegacyAccounting == nil || *old.Options.LegacyAccounting != *fresh.Options.LegacyAccounting || fresh.Options.TransferAccounting != nil) {
				return errors.New("legacy journal change requires reconciled rollout")
			}
		}
		if !found {
			return errors.New("reliable accounting scope removal requires reconciled rollout")
		}
	}
	return nil
}
