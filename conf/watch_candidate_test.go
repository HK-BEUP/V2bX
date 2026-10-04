package conf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeWatchFixture(t *testing.T, path, level string) {
	t.Helper()
	data := fmt.Sprintf(`{"Log":{"Level":%q},"Cores":[{"Type":"xray"}],"Nodes":[{"ApiHost":"https://panel.example.invalid","NodeID":42,"NodeType":"vless"}]}`, level)
	if err := os.WriteFile(path+".new", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateWatchSerializationAndJoin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	writeWatchFixture(t, file, "initial")
	entered := make(chan *Conf, 4)
	release := make(chan struct{})
	var calls atomic.Int32
	stop, err := watchCandidate(file, "", "", 10*time.Millisecond, func(c *Conf) error {
		calls.Add(1)
		entered <- c
		<-release
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer func() { unblock(); stop() }()
	writeWatchFixture(t, file, "first")
	var first *Conf
	select {
	case first = <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first atomic replace not observed")
	}
	writeWatchFixture(t, file, "second")
	time.Sleep(40 * time.Millisecond)
	if calls.Load() != 1 || first.LogConfig.Level != "first" {
		t.Fatal("running configuration overwritten or callback overlapped")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop returned before in-flight reload completed")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher failed to join")
	}
	writeWatchFixture(t, file, "third")
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("queued reload ran after cancellation")
	}
}

func TestCandidateWatchRejectsBrokenFileAndSurvivesReplacement(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	writeWatchFixture(t, file, "initial")
	levels := make(chan string, 8)
	stop, err := watchCandidate(file, "", "", 10*time.Millisecond, func(c *Conf) error { levels <- c.LogConfig.Level; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, bad := range []string{`{invalid`, `{"Cores":[],"Nodes":[]}`} {
		if err := os.WriteFile(file, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-levels:
			t.Fatal("invalid or empty config reached host")
		case <-time.After(60 * time.Millisecond):
		}
	}
	for _, level := range []string{"one", "two"} {
		writeWatchFixture(t, file, level)
		select {
		case got := <-levels:
			if got != level {
				t.Fatalf("got %s", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("atomic replacement watch lost")
		}
	}
}

func TestTransferReloadCannotDowngradeAccounting(t *testing.T) {
	fixture := func() *Conf {
		return &Conf{NodeConfig: []NodeConfig{{ApiConfig: ApiConfig{APIHost: "https://panel.example.invalid", NodeID: 42, NodeType: "vless"}, Options: Options{TransferAccounting: &TransferAccountingConfig{Epoch: "a", Directory: "/synthetic/private"}}}}}
	}
	current := fixture()
	for _, change := range []func(*Conf){func(c *Conf) { c.NodeConfig = nil }, func(c *Conf) { c.NodeConfig[0].Options.TransferAccounting = nil }, func(c *Conf) { c.NodeConfig[0].Options.TransferAccounting.Epoch = "b" }, func(c *Conf) { c.NodeConfig[0].Options.TransferAccounting.Directory = "/other" }, func(c *Conf) { c.NodeConfig = append(c.NodeConfig, c.NodeConfig[0]) }} {
		next := fixture()
		change(next)
		if ValidateTransferReload(current, next) == nil {
			t.Fatal("unsafe accounting replacement accepted")
		}
	}
	next := fixture()
	next.NodeConfig[0].Options.Name = "new-tag"
	if err := ValidateTransferReload(current, next); err != nil {
		t.Fatal("normal settings cannot reload", err)
	}
}
