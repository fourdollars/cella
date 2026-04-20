package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fourdoors/cella/internal/lxd"
	"github.com/fourdoors/cella/internal/proxy"
	"github.com/fourdoors/cella/internal/runtime"
	"github.com/spf13/cobra"
)

func proxyCellaDataDir() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			return filepath.Join(u.HomeDir, ".cella")
		}
	}
	return os.ExpandEnv("$HOME/.cella")
}

func proxyCmd() *cobra.Command {
	var (
		port         int
		containers   []string
		autoApprove  bool
		permanent    bool
		mitmEnabled  bool
		cleanupCA    bool
		patEnv       string
		tokenID      string
		poolName     string
		allowDomains []string
		bridgeHostIP string
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run transparent proxy headlessly for selected LXD containers",
		Long: `Run cella transparent proxy without TUI.

This command can:
- start MITM-capable transparent listener
- set nftables REDIRECT for selected containers
- bootstrap a minimal broker runtime state from a PAT env
- auto-approve domains for unattended E2E tests`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(containers) == 0 {
				return fmt.Errorf("at least one --container is required")
			}

			containerIPs, lxdSocketPath, err := resolveLXDContainerIPs(containers)
			if err != nil {
				return err
			}

			dataDir := proxyCellaDataDir()
			approvalCh := make(chan proxy.ApprovalRequest, 128)
			srv := proxy.NewServer(port, approvalCh)

			if mitmEnabled {
				mitmCfg, err := proxy.NewMITMConfig(dataDir)
				if err != nil {
					return fmt.Errorf("create mitm config: %w", err)
				}
				srv.EnableMITM(mitmCfg)
			}

			_ = srv.LoadAllowlistsFromDir(dataDir)
			_ = srv.LoadDenylistsFromDir(dataDir)

			tl := proxy.NewTransparentListener(port, srv)
			tl.SetOnPermanentAllow(func() { _ = srv.SaveAllowlistsToDir(dataDir) })
			tl.SetOnPermanentDeny(func() { _ = srv.SaveDenylistsToDir(dataDir) })
			if err := tl.Start(); err != nil {
				return fmt.Errorf("start listener :%d: %w", port, err)
			}

			for _, c := range containers {
				ip := containerIPs[c]
				if err := proxy.SetupTransparentRedirect(ip, port); err != nil {
					tl.Stop()
					for _, rollback := range containers {
						if oldIP := containerIPs[rollback]; oldIP != "" {
							_ = proxy.RemoveTransparentRedirect(oldIP)
						}
					}
					return fmt.Errorf("setup redirect for %s (%s): %w", c, ip, err)
				}
			}

			if mitmEnabled {
				if strings.TrimSpace(bridgeHostIP) == "" {
					bridgeHostIP = proxy.DetectBridgeIP()
				}
				setup := &proxy.AutoSetup{ProxyHost: bridgeHostIP, ProxyPort: port, MITMPem: srv.MITMCAPem()}
				for _, c := range containers {
					if err := setup.SetupContainer(lxdSocketPath, c); err != nil {
						tl.Stop()
						for _, rollback := range containers {
							if oldIP := containerIPs[rollback]; oldIP != "" {
								_ = proxy.RemoveTransparentRedirect(oldIP)
							}
						}
						return fmt.Errorf("inject mitm trust into %s: %w", c, err)
					}
				}
			}

			ipMap := make(map[string]string, len(containerIPs))
			for name, ip := range containerIPs {
				ipMap[ip] = name
			}
			srv.UpdateContainerMap(ipMap)

			if strings.TrimSpace(patEnv) != "" {
				if strings.TrimSpace(tokenID) == "" {
					tokenID = "tok-broker"
				}
				if strings.TrimSpace(poolName) == "" {
					poolName = "pool_main"
				}
				groups := make([]proxy.BrokerGroupState, 0, len(containers))
				for _, c := range containers {
					groups = append(groups, proxy.BrokerGroupState{ID: c, Name: c, Match: c, Pool: poolName, Weight: 1})
				}
				srv.SetBrokerState(proxy.BrokerState{
					AppliedAt: time.Now(),
					Groups:    groups,
					Pools: []proxy.BrokerPoolState{{
						Name: poolName,
						Tokens: []proxy.BrokerTokenState{{
							ID:           tokenID,
							Enabled:      true,
							Health:       0.95,
							RemainingRPH: 10000,
							PATEnv:       patEnv,
						}},
					}},
				})
			}

			if len(allowDomains) > 0 {
				for _, c := range containers {
					al := srv.GetAllowlist(c)
					for _, d := range allowDomains {
						d = strings.TrimSpace(d)
						if d != "" {
							al.Add(d)
						}
					}
				}
				_ = srv.SaveAllowlistsToDir(dataDir)
			}

			go func() {
				for req := range approvalCh {
					if verbose {
						fmt.Printf("[approval] container=%s domain=%s method=%s path=%s\n", req.Container, req.Domain, req.Method, req.Path)
					}
					if autoApprove {
						resp := proxy.ApprovalResponse{Approved: true, Permanent: permanent}
						select {
						case req.ResponseCh <- resp:
						default:
						}
						continue
					}
					fmt.Fprintf(os.Stderr, "approval pending for %s -> %s (%s); auto-approve disabled, deny by default\n", req.Container, req.Domain, req.Method)
					select {
					case req.ResponseCh <- proxy.ApprovalResponse{Approved: false, Permanent: false}:
					default:
					}
				}
			}()

			if verbose {
				go func() {
					lastAudit := 0
					lastBrokerSig := ""
					ticker := time.NewTicker(1500 * time.Millisecond)
					defer ticker.Stop()
					for range ticker.C {
						entries := srv.Audit().All()
						if len(entries) > lastAudit {
							for _, e := range entries[lastAudit:] {
								fmt.Printf("[audit] %s status=%s method=%s container=%s domain=%s path=%s code=%d tls=%v broker_token=%s broker_src=%s latency=%s\n",
									e.Time.Format("15:04:05"), e.Status, e.Method, e.Container, e.Domain, e.Path, e.RespCode, e.TLS, e.BrokerTokenID, e.BrokerAuthSource, e.Latency.Truncate(time.Millisecond))
							}
							lastAudit = len(entries)
						}

						brokerSig, brokerLines := brokerVerboseSnapshot(srv.BrokerState())
						if brokerSig != lastBrokerSig {
							for _, line := range brokerLines {
								fmt.Println(line)
							}
							lastBrokerSig = brokerSig
						}
					}
				}()
			}

			names := make([]string, 0, len(containerIPs))
			for name := range containerIPs {
				names = append(names, name)
			}
			sort.Strings(names)
			fmt.Printf("✅ transparent proxy listening on :%d\n", port)
			fmt.Printf("✅ redirects active for containers: %s\n", strings.Join(names, ", "))
			if strings.TrimSpace(patEnv) != "" {
				fmt.Printf("✅ broker bootstrap active: pool=%s token=%s pat_env=%s\n", poolName, tokenID, patEnv)
			}
			fmt.Printf("ℹ press Ctrl+C to cleanup redirects and stop proxy\n")

			var cleanupOnce sync.Once
			cleanup := func(reason string) {
				cleanupOnce.Do(func() {
					tl.Stop()
					for _, c := range containers {
						if ip := containerIPs[c]; ip != "" {
							_ = proxy.RemoveTransparentRedirect(ip)
						}
					}
					if mitmEnabled && cleanupCA {
						setup := &proxy.AutoSetup{}
						for _, c := range containers {
							_ = setup.RemoveSetup(lxdSocketPath, c)
						}
					}
					fmt.Printf("🧹 proxy stopped, redirects removed (%s)\n", reason)
				})
			}
			defer cleanup("exit")

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
			sig := <-sigCh
			cleanup(fmt.Sprintf("signal=%s", sig))
			return nil
		},
	}

	cmd.Flags().IntVar(&port, "port", 9081, "Transparent listener port")
	cmd.Flags().StringArrayVar(&containers, "container", nil, "LXD container name to intercept (repeatable)")
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", true, "Auto-approve proxy requests in headless mode")
	cmd.Flags().BoolVar(&permanent, "permanent", true, "When auto-approving, persist allow decisions")
	cmd.Flags().BoolVar(&mitmEnabled, "mitm", true, "Enable MITM TLS interception")
	cmd.Flags().BoolVar(&cleanupCA, "cleanup-ca", false, "Remove injected MITM CA from containers on shutdown")
	cmd.Flags().StringVar(&bridgeHostIP, "bridge-host", "", "Host bridge IP for AutoSetup metadata (auto-detect by default)")
	cmd.Flags().StringVar(&patEnv, "pat-env", "", "PAT env key for minimal broker bootstrap (e.g. CELLA_BROKER_TEST_PAT)")
	cmd.Flags().StringVar(&tokenID, "token-id", "tok-broker", "Token ID used in minimal broker bootstrap")
	cmd.Flags().StringVar(&poolName, "pool", "pool_main", "Pool name used in minimal broker bootstrap")
	cmd.Flags().StringArrayVar(&allowDomains, "allow-domain", []string{"api.github.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com"}, "Pre-allow domains (repeatable)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Print approvals and audit entries while running")

	return cmd
}

func brokerVerboseSnapshot(st proxy.BrokerState) (string, []string) {
	lines := make([]string, 0)
	for _, p := range st.Pools {
		for _, tkn := range p.Tokens {
			line := fmt.Sprintf("[broker] pool=%s token=%s enabled=%v health=%.2f rph=%d session_state=%s last_test=%s auth_env=%s",
				p.Name,
				tkn.ID,
				tkn.Enabled,
				tkn.Health,
				tkn.RemainingRPH,
				strings.TrimSpace(tkn.SessionState),
				strings.TrimSpace(tkn.LastTest),
				strings.TrimSpace(tkn.PATEnv),
			)
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "[broker] pools=0 tokens=0")
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), lines
}

func resolveLXDContainerIPs(names []string) (map[string]string, string, error) {
	client, err := lxd.NewClient("")
	if err != nil {
		return nil, "", fmt.Errorf("init lxd client: %w", err)
	}
	rt := runtime.NewLXDRuntime(client)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	containers, err := rt.ListContainers(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("list lxd containers: %w", err)
	}

	idx := make(map[string]runtime.ContainerInfo, len(containers))
	for _, c := range containers {
		idx[c.Name] = c
	}

	result := make(map[string]string, len(names))
	for _, name := range names {
		c, ok := idx[name]
		if !ok {
			return nil, "", fmt.Errorf("container %s not found", name)
		}
		if strings.ToLower(c.Status) != "running" {
			return nil, "", fmt.Errorf("container %s is not running (status=%s)", name, c.Status)
		}
		if netIP := strings.TrimSpace(c.IP); netIP == "" || netIP == "-" {
			return nil, "", fmt.Errorf("container %s has no usable IP", name)
		} else {
			result[name] = netIP
		}
	}

	return result, client.SocketPath(), nil
}
