//go:build linux || darwin

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/InazumaV/V2bX/common/beupguard"
)

type initialization struct {
	RuntimePath string                    `json:"runtime_path"`
	PullPath    string                    `json:"pull_path"`
	APIBase     string                    `json:"api_base"`
	Settings    beupguard.RuntimeSettings `json:"settings"`
}

func initialize(reader io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(reader, 8193))
	if err != nil || len(b) > 8192 {
		return "", errors.New("invalid initialization input")
	}
	var in initialization
	if err = json.Unmarshal(b, &in); err != nil {
		return "", errors.New("invalid initialization input")
	}
	s := in.Settings
	u, err := url.Parse(in.APIBase)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "/api/v1/subscription-protection/grants/node/"+s.Node {
		return "", errors.New("invalid control endpoint")
	}
	key, err := hex.DecodeString(s.CommandPublicKey)
	if err != nil || len(key) != 32 || s.Version != 1 || !s.AuthorizationOnly || len(s.RequiredTags) != 1 || s.RequiredTags[0] == "" || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(s.Node) {
		return "", errors.New("invalid independent runtime settings")
	}
	journal := filepath.Join(s.StateDirectory, "journal.json")
	paths := []string{in.PullPath, journal, in.RuntimePath}
	seen := map[string]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || seen[p] {
			return "", errors.New("invalid initialization path")
		}
		seen[p] = true
		dir := filepath.Dir(p)
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil || resolved != dir {
			return "", errors.New("private initialization directory required")
		}
		st, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Geteuid() || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return "", errors.New("private initialization directory required")
		}
		if _, err = os.Lstat(p); !os.IsNotExist(err) {
			return "", errors.New("initialization target already exists")
		}
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(private)
	pull, err := json.Marshal(beupguard.PullSettings{Version: 1, Node: s.Node, APIBase: in.APIBase, StateDirectory: s.StateDirectory, ReceiptPrivateKey: hex.EncodeToString(private)})
	if err != nil {
		return "", err
	}
	defer clear(pull)
	state, _ := json.Marshal(map[string]any{"version": 1, "node": s.Node, "records": []any{}})
	runtime, _ := json.Marshal(s)
	contents := [][]byte{pull, state, runtime}
	created := []string{}
	for i, p := range paths {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err == nil {
			created = append(created, p)
			_, err = f.Write(contents[i])
			if err == nil {
				err = f.Sync()
			}
			ce := f.Close()
			if err == nil {
				err = ce
			}
		}
		if err != nil {
			for _, own := range created {
				_ = os.Remove(own)
			}
			return "", errors.New("initialization failed; new files removed")
		}
	}
	return hex.EncodeToString(pub), nil
}
