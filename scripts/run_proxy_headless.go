//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fourdoors/cella/internal/proxy"
)

func main() {
	dataDir := os.ExpandEnv("$HOME/.cella")
	approvalCh := make(chan proxy.ApprovalRequest, 100)
	srv := proxy.NewServer(9081, approvalCh)

	go func() {
		for req := range approvalCh {
			req.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: false}
		}
	}()

	mitmCfg, err := proxy.NewMITMConfig(dataDir)
	if err != nil {
		fmt.Printf("MITM cfg error: %v\n", err)
		os.Exit(1)
	}
	srv.EnableMITM(mitmCfg)

	st := proxy.BrokerState{
		ExchangeMode: "real",
		Groups: []proxy.BrokerGroupState{
			{ID: "ci", Match: "127.0.0.1", Pool: "ci-pool"},
		},
		Pools: []proxy.BrokerPoolState{{
			Name: "ci-pool",
			Tokens: []proxy.BrokerTokenState{{
				ID: "tok_ci1", Enabled: true, Health: 1.0, RemainingRPH: 1000, PATEnv: "CELLA_BROKER_TEST_PAT",
			}},
		}},
	}
	srv.SetBrokerState(st)

	tl := proxy.NewTransparentListener(9081, srv)
	if err := tl.Start(); err != nil {
		fmt.Printf("Listener error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Listening on :9081")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
