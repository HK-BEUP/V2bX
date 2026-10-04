package cmd

import (
	"errors"
	"github.com/InazumaV/V2bX/common/beupguard"
	beupobserve "github.com/InazumaV/V2bX/common/beupobserve"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/InazumaV/V2bX/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run V2bX server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/V2bX/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		}
		log.SetOutput(f)
	}
	limiter.Init()
	stopGuard, guardErr := beupguard.StartFromEnvironment()
	if guardErr != nil {
		log.Error("BEUP isolation startup incomplete; verify each controller status, proxy service continues")
	}
	defer stopGuard()
	stopObservation, observationErr := beupobserve.StartFromEnvironment()
	if observationErr != nil {
		log.Error("BEUP observation settings rejected; proxy continues without telemetry")
	}
	defer stopObservation()
	log.Info("Start V2bX...")
	vc, err := vCore.NewCore(c.CoresConfig)
	if err != nil {
		log.WithField("err", err).Error("new core failed")
		return
	}
	err = vc.Start()
	if err != nil {
		log.WithField("err", err).Error("Start core failed")
		return
	}
	// Serialize shutdown and watched configuration replacement.
	var lifecycle sync.Mutex
	stopping := false
	log.Info("Core ", vc.Type(), " started")
	nodes := node.New()
	defer func() {
		lifecycle.Lock()
		defer lifecycle.Unlock()
		stopping = true
		if err := nodes.Close(); err != nil {
			log.Error("Node accounting shutdown incomplete; retain journal and reconcile before restart")
		}
		if vc != nil {
			if err := vc.Close(); err != nil {
				log.Error("Core close failed")
			}
		}
	}()
	err = nodes.Start(c.NodeConfig, vc)
	if err != nil {
		log.WithField("err", err).Error("Run nodes failed")
		return
	}
	log.Info("Nodes started")
	xdns := os.Getenv("XRAY_DNS_PATH")
	sdns := os.Getenv("SING_DNS_PATH")
	if watch {
		stopWatch, watchErr := conf.WatchCandidate(config, xdns, sdns, func(next *conf.Conf) error {
			lifecycle.Lock()
			defer lifecycle.Unlock()
			if stopping {
				return errors.New("server stopping")
			}
			if err := conf.ValidateTransferReload(c, next); err != nil {
				return err
			}
			if err := nodes.Close(); err != nil {
				log.Error("Reload refused: accounting shutdown incomplete; journal retained")
				return err
			}
			beupobserve.Reset()
			if err := vc.Close(); err != nil {
				return err
			}
			beupguard.ResetBindings()
			candidate, err := vCore.NewCore(next.CoresConfig)
			if err != nil {
				return err
			}
			vc = candidate
			if err = vc.Start(); err != nil {
				return err
			}
			c = next
			if err = nodes.Start(c.NodeConfig, vc); err != nil {
				return err
			}
			log.Info("Nodes restarted")
			runtime.GC()
			return nil
		})
		if watchErr != nil {
			log.Error("Start configuration watcher failed")
			return
		}
		// Registered after node cleanup, so stop and join watcher first.
		defer stopWatch()
	}
	// clear memory
	runtime.GC()
	// wait exit signal
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
		<-osSignals
	}
}
