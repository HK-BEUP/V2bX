//go:build linux || darwin

package beupguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var runtimeStartMu sync.Mutex

func StartFromEnvironment() (func(), error) { return startFromEnvironment(time.Now, KernelBootStamp) }

func startFromEnvironment(now func() time.Time, boot func() (BootStamp, error)) (func(), error) {
	primary, directory := os.Getenv("BEUP_GUARD_CONFIG"), os.Getenv("BEUP_SUBSCRIPTION_CONFIG_DIR")
	stop, err := startConfigured(primary, directory, now, boot)
	// A broken new subscription configuration must not disable an existing attack
	// controller. Its signed journal is reopened unchanged, including active holds.
	if err != nil && primary != "" && directory != "" && !Enabled() {
		fallback, primaryErr := startConfigured(primary, "", now, boot)
		if primaryErr == nil {
			return fallback, errors.New("subscription isolation unavailable; existing primary retained")
		}
	}
	return stop, err
}
func startConfigured(primaryPath, directory string, now func() time.Time, boot func() (BootStamp, error)) (func(), error) {
	runtimeStartMu.Lock()
	defer runtimeStartMu.Unlock()
	noop := func() {}
	if primaryPath == "" && directory == "" {
		return noop, nil
	}
	if Enabled() {
		return noop, errors.New("isolation already active")
	}
	var settings []RuntimeSettings
	if primaryPath != "" {
		s, err := LoadRuntimeSettings(primaryPath)
		if err != nil {
			return noop, err
		}
		settings = append(settings, s)
	}
	if directory != "" {
		if !filepath.IsAbs(directory) || privateDir(directory) != nil {
			return noop, errors.New("private subscription settings directory required")
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return noop, err
		}
		count := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			count++
			if count > 32 {
				return noop, errors.New("too many subscription runtimes")
			}
			s, err := LoadRuntimeSettings(filepath.Join(directory, entry.Name()))
			if err != nil {
				return noop, err
			}
			if !s.AuthorizationOnly || len(s.RequiredTags) != 1 {
				return noop, errors.New("subscription runtime requires one inbound and independent authorizations")
			}
			settings = append(settings, s)
		}
		if count == 0 {
			return noop, errors.New("subscription settings directory is empty")
		}
	}
	nodes, dirs, tags := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range settings {
		dir := filepath.Clean(s.StateDirectory)
		if nodes[s.Node] || dirs[dir] {
			return noop, errors.New("duplicate isolation runtime identity or journal")
		}
		nodes[s.Node], dirs[dir] = true, true
		if s.AuthorizationOnly {
			for _, tag := range s.RequiredTags {
				if tags[tag] {
					return noop, errors.New("overlapping subscription inbound scopes")
				}
				tags[tag] = true
			}
		}
	}
	var runtimes []*Runtime
	closeAll := func() {
		for i := len(runtimes) - 1; i >= 0; i-- {
			runtimes[i].Close()
		}
	}
	group := &guardGroup{}
	for i, s := range settings {
		r, err := startRuntime(s, now, boot)
		if err != nil {
			closeAll()
			return noop, err
		}
		runtimes = append(runtimes, r)
		entry := scopedGuard{guard: r.guard}
		if i == 0 && primaryPath != "" {
			group.primary = r.guard
		} else {
			entry.tags = map[string]bool{}
			for _, tag := range s.RequiredTags {
				entry.tags[tag] = true
			}
		}
		group.entries = append(group.entries, entry)
	}
	active.Store(group)
	var once sync.Once
	return func() {
		once.Do(func() {
			runtimeStartMu.Lock()
			defer runtimeStartMu.Unlock()
			active.CompareAndSwap(group, nil)
			closeAll()
		})
	}, nil
}
