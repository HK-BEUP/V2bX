//go:build linux || darwin

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/InazumaV/V2bX/common/beupguard"
)

func TestInitializePrivateNodeIdentityAndRefuseOverwrite(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	in := initialization{RuntimePath: filepath.Join(dir, "runtime.json"), PullPath: filepath.Join(dir, "pull.json"), APIBase: "https://synthetic.example/api/v1/subscription-protection/grants/node/test-a", Settings: beupguard.RuntimeSettings{Version: 1, Node: "test-a", StateDirectory: dir, CommandPublicKey: hex.EncodeToString(pub), RequiredTags: []string{"a"}, AllowBlocks: true, AuthorizationOnly: true}}
	b, _ := json.Marshal(in)
	receipt, err := initialize(bytes.NewReader(b))
	if err != nil || len(receipt) != 64 {
		t.Fatal("initialization failed", err)
	}
	settings, err := beupguard.LoadPullSettings(in.PullPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := hex.DecodeString(settings.ReceiptPrivateKey)
	if err != nil || !bytes.Equal(ed25519.NewKeyFromSeed(private[:32]), private) || hex.EncodeToString(private[32:]) != receipt {
		t.Fatal("receipt key mismatch")
	}
	for _, path := range []string{in.PullPath, in.RuntimePath, filepath.Join(dir, "journal.json")} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("public identity file", path, err)
		}
	}
	before, _ := os.ReadFile(in.PullPath)
	if _, err = initialize(bytes.NewReader(b)); err == nil {
		t.Fatal("overwrote existing receipt identity")
	}
	after, _ := os.ReadFile(in.PullPath)
	if !bytes.Equal(before, after) {
		t.Fatal("identity changed")
	}
}
func TestInitializeRejectsWrongScopeOrPublicDirectory(t *testing.T) {
	for _, mode := range []string{"legacy", "two-tags", "public-dir", "insecure-endpoint", "duplicate-path"} {
		t.Run(mode, func(t *testing.T) {
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			os.Chmod(dir, 0700)
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			in := initialization{RuntimePath: filepath.Join(dir, "runtime.json"), PullPath: filepath.Join(dir, "pull.json"), APIBase: "https://synthetic.example/api/v1/subscription-protection/grants/node/test-a", Settings: beupguard.RuntimeSettings{Version: 1, Node: "test-a", StateDirectory: dir, CommandPublicKey: hex.EncodeToString(pub), RequiredTags: []string{"a"}, AllowBlocks: true, AuthorizationOnly: true}}
			switch mode {
			case "legacy":
				in.Settings.AuthorizationOnly = false
			case "two-tags":
				in.Settings.RequiredTags = []string{"a", "b"}
			case "public-dir":
				os.Chmod(dir, 0755)
			case "insecure-endpoint":
				in.APIBase = "http://synthetic.example/"
			case "duplicate-path":
				in.RuntimePath = in.PullPath
			}
			b, _ := json.Marshal(in)
			if _, err := initialize(bytes.NewReader(b)); err == nil {
				t.Fatal("invalid initialization accepted")
			}
			if _, err := os.Stat(in.PullPath); !os.IsNotExist(err) {
				t.Fatal("rejected initialization wrote a key")
			}
		})
	}
}
