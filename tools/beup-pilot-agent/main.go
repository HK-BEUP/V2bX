//go:build linux || darwin

// Separate bounded polling process; never started implicitly by the proxy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/InazumaV/V2bX/common/beupguard"
)

func main() {
	path := flag.String("config", "", "absolute path to private node-local settings")
	initMode := flag.Bool("initialize", false, "initialize a new private independent node from stdin; print public receipt key only")
	flag.Parse()
	if *initMode {
		key, err := initialize(os.Stdin)
		if err != nil {
			log.Print("private node initialization rejected")
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"receipt_public_key": key})
		return
	}
	log.SetFlags(log.LstdFlags | log.LUTC)
	s, e := beupguard.LoadPullSettings(*path)
	if e != nil {
		log.Print("pilot settings unavailable")
		os.Exit(1)
	}
	agent, e := beupguard.NewPullAgent(s)
	if e != nil {
		log.Print("pilot agent initialization failed")
		os.Exit(1)
	}
	defer agent.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	failed := false
	agent.Run(ctx, func(e error) {
		if ctx.Err() != nil {
			return
		}
		if e != nil && !failed {
			log.Print("pilot control unavailable or unconfirmed; local leases remain authoritative")
			failed = true
		}
		if e == nil && failed {
			log.Print("pilot control communication recovered")
			failed = false
		}
	})
}
