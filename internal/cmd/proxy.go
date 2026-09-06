package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/github/gh-aw-mcpg/internal/config"
	"github.com/github/gh-aw-mcpg/internal/delegation"
	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/enclavegithub"
	"github.com/github/gh-aw-mcpg/internal/envutil"
	"github.com/github/gh-aw-mcpg/internal/githubhttp"
	"github.com/github/gh-aw-mcpg/internal/httputil"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/proxy"
	"github.com/github/gh-aw-mcpg/internal/util"
	"github.com/spf13/cobra"
)

var logProxyCmd = logger.ForFile()

// DefaultProxyListenAddr is the default listen address used by the proxy command.
const DefaultProxyListenAddr = DefaultListenIPv4 + ":8080"

// Proxy subcommand flag variables
var (
	proxyGuardWasm       string
	proxyPolicy          string
	proxyToken           string
	proxyListen          string
	proxyLogDir          string
	proxyWasmCacheDir    string
	proxyDIFCMode        string
	proxyAPIURL          string
	proxyTLS             bool
	proxyTLSDir          string
	proxyTLSDNSNames     []string
	proxyTrustedBots     []string
	proxyTrustedUsers    []string
	proxyOTLPEndpoint    string
	proxyOTLPService     string
	proxyOTLPSampleRate  float64
	proxyForcePublicRepo bool
)

func init() {
	rootCmd.AddCommand(newProxyCmd())
}

func resolveDelegationProxyConfig() (*proxy.DelegationConfig, string, error) {
	envelopeJSON := os.Getenv("MCP_GATEWAY_DELEGATION_ENVELOPE")
	capabilityKey := os.Getenv(delegation.EnvControlCapabilityKey)
	statePath := os.Getenv("MCP_GATEWAY_DELEGATION_STATE_PATH")
	generationRaw := os.Getenv("MCP_GATEWAY_DELEGATION_GENERATION")
	controlListenAddr := os.Getenv(delegation.EnvControlListenAddr)
	if envelopeJSON == "" && capabilityKey == "" && statePath == "" && generationRaw == "" && controlListenAddr == "" {
		return nil, "", nil
	}
	if envelopeJSON == "" || capabilityKey == "" || statePath == "" || generationRaw == "" || controlListenAddr == "" {
		return nil, "", fmt.Errorf("MCP_GATEWAY_DELEGATION_ENVELOPE, %s, MCP_GATEWAY_DELEGATION_STATE_PATH, %s, and MCP_GATEWAY_DELEGATION_GENERATION must be configured together", delegation.EnvControlCapabilityKey, delegation.EnvControlListenAddr)
	}
	var envelope delegation.Envelope
	decoder := json.NewDecoder(bytes.NewReader([]byte(envelopeJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, "", fmt.Errorf("invalid delegation envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, "", fmt.Errorf("invalid delegation envelope: trailing JSON")
	}
	generation, err := strconv.ParseUint(generationRaw, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid delegation generation: %w", err)
	}
	capability, err := delegation.NewControlCapability(capabilityKey)
	if err != nil {
		return nil, "", err
	}
	store, err := delegation.LoadStore(statePath, &envelope, generation)
	if err != nil {
		return nil, "", err
	}
	return &proxy.DelegationConfig{Store: store, Capability: capability, StatePath: statePath, ControlListenAddr: controlListenAddr}, statePath, nil
}

func newProxyCmd() *cobra.Command {
	defaultGuard := detectGuardWasm()
	defaultProxyLogDir := envutil.GetEnvString("MCP_GATEWAY_LOG_DIR", config.DefaultLogDir)

	cmd := &cobra.Command{
		Use:     "proxy",
		GroupID: "modes",
		Short:   "Run as a GitHub API filtering proxy",
		Long: `Run the gateway in proxy mode — an HTTP(S) forward proxy that intercepts
gh CLI requests and applies DIFC filtering using the same guard WASM module.

Container usage (uses baked-in guard automatically):

  docker run --rm -p 8443:8443 \
    -e GITHUB_TOKEN \
    -v /tmp/proxy-logs:/tmp/gh-aw/mcp-logs \
    ghcr.io/github/gh-aw-mcpg:latest proxy \
    --policy '{"allow-only":{"repos":["org/repo"],"min-integrity":"approved"}}' \
    --listen 0.0.0.0:8443 \
    --tls

  # Trust the CA cert from the mounted volume
  export GH_HOST=localhost:8443
  export NODE_EXTRA_CA_CERTS=/tmp/proxy-logs/proxy-tls/ca.crt
  gh issue list -R org/repo

Local usage:

  awmg proxy \
    --guard-wasm guards/github-guard/github_guard.wasm \
    --policy '{"allow-only":{"repos":["org/repo"],"min-integrity":"approved"}}' \
    --listen localhost:8443 --tls`,
		Example: `  # Run with auto-detected baked-in guard (container image)
  awmg proxy --policy '{"allow-only":{"repos":["org/repo"],"min-integrity":"approved"}}'

  # Run locally with explicit guard WASM and TLS
  awmg proxy \
    --guard-wasm guards/github-guard/github_guard.wasm \
    --policy '{"allow-only":{"repos":["org/repo"]}}' \
    --listen localhost:8443 --tls`,
		SilenceUsage: true,
		RunE:         runProxy,
	}

	guardHelp := "Path to the guard WASM module"
	if defaultGuard != "" {
		guardHelp += " (auto-detected: " + defaultGuard + ")"
	} else {
		guardHelp += " (required)"
	}
	// Note: --listen and --log-dir are re-declared here (not inherited from rootCmd as
	// persistent flags) because the proxy subcommand has different defaults and a distinct
	// purpose: it runs as a standalone HTTPS forward proxy, not an MCP gateway. Keeping
	// them independent avoids confusion and allows each command to evolve separately.
	cmd.Flags().StringVar(&proxyGuardWasm, "guard-wasm", defaultGuard, guardHelp)
	cmd.Flags().StringVar(&proxyPolicy, "policy", envutil.GetEnvString(config.EnvGuardPolicyJSON, ""), "Guard policy JSON")
	if err := cmd.RegisterFlagCompletionFunc("policy", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return cobra.AppendActiveHelp(nil,
				"Tip: Pass a JSON guard policy, e.g. --policy '{\"allow-only\":{\"repos\":\"public\",\"min-integrity\":\"none\"}}'"),
			cobra.ShellCompDirectiveNoFileComp
	}); err != nil {
		logProxyCmd.Printf("Failed to register completion for --policy: %v", err)
	}
	cmd.Flags().StringVar(&proxyToken, "github-token", "", "Fallback GitHub API token (default: forwards client Authorization header)")
	cmd.Flags().StringVarP(&proxyListen, "listen", "l", DefaultProxyListenAddr, "Proxy listen address")
	cmd.Flags().StringVar(&proxyLogDir, "log-dir", defaultProxyLogDir, "Log file directory")
	cmd.Flags().StringVar(&proxyWasmCacheDir, "wasm-cache-dir", resolveWasmCacheDir(false, "", defaultProxyLogDir), "Directory for disk-backed wazero compilation cache (default: sibling of <log-dir>, named wazero-cache)")
	registerGuardsModeFlag(cmd, &proxyDIFCMode)
	cmd.Flags().StringVar(&proxyAPIURL, "github-api-url", "", "Upstream GitHub API URL (default: auto-derived from GITHUB_API_URL or GITHUB_SERVER_URL, falls back to https://api.github.com)")
	cmd.Flags().BoolVar(&proxyForcePublicRepo, "force-public-repos", envutil.GetEnvBool(config.EnvForcePublicRepos, true), "When true (default), forces repos=\"public\" at runtime if the workflow repo is public. Set to false to disable.")
	cmd.Flags().BoolVar(&proxyTLS, "tls", false, "Enable HTTPS with auto-generated self-signed certificates")
	cmd.Flags().StringVar(&proxyTLSDir, "tls-dir", "", "Directory for TLS certificates (default: <log-dir>/proxy-tls)")
	cmd.Flags().StringSliceVar(&proxyTLSDNSNames, "tls-dns-name", nil, "Additional DNS name for the generated TLS certificate (repeatable or comma-separated; requires --tls)")
	cmd.Flags().StringSliceVar(&proxyTrustedBots, "trusted-bots", nil, "Additional trusted bot usernames (comma-separated, extends built-in list)")
	cmd.Flags().StringSliceVar(&proxyTrustedUsers, "trusted-users", nil, "User logins that receive approved integrity (comma-separated)")
	registerTracingFlags(cmd, &proxyOTLPEndpoint, &proxyOTLPService, &proxyOTLPSampleRate,
		"OTLP HTTP endpoint for trace export (e.g. http://localhost:4318). Tracing is disabled when empty.",
		"Service name reported in traces.",
		"Fraction of traces to sample and export (0.0–1.0).")

	// Only require --guard-wasm when no baked-in guard is available
	if defaultGuard == "" {
		cmd.MarkFlagRequired("guard-wasm")
	}

	// Use MarkFlagDirname for directory flags (cobra best practice)
	for _, dirFlag := range []string{"log-dir", "wasm-cache-dir", "tls-dir"} {
		if err := cmd.MarkFlagDirname(dirFlag); err != nil {
			logProxyCmd.Printf("Failed to register --%s dirname completion: %v", dirFlag, err)
		}
	}

	return cmd
}

func resolveEnclaveProxyConfig(
	policyRaw string,
	capabilityKey string,
	explicitGuardPolicy string,
	trustedBots []string,
	trustedUsers []string,
) (*proxy.EnclaveConfig, string, bool, error) {
	enabled := policyRaw != "" || capabilityKey != ""
	if !enabled {
		return nil, "", false, nil
	}
	if policyRaw == "" || capabilityKey == "" {
		return nil, "", true, fmt.Errorf(
			"%s and %s must be configured together",
			enclavegithub.EnvPolicyJSON,
			enclavegithub.EnvCapabilityKey,
		)
	}
	if explicitGuardPolicy != "" {
		return nil, "", true, fmt.Errorf(
			"--policy and %s cannot be combined",
			enclavegithub.EnvPolicyJSON,
		)
	}
	if len(trustedBots) != 0 || len(trustedUsers) != 0 {
		return nil, "", true, fmt.Errorf(
			"trusted bot and user overrides are not supported in enclave proxy mode",
		)
	}

	policy, err := enclavegithub.ParsePolicy(policyRaw)
	if err != nil {
		return nil, "", true, err
	}
	verifier, err := enclavegithub.NewVerifier(capabilityKey, policy)
	if err != nil {
		return nil, "", true, err
	}
	guardPolicy, err := policy.GuardPolicyJSON()
	if err != nil {
		return nil, "", true, err
	}
	return &proxy.EnclaveConfig{Policy: policy, Verifier: verifier}, guardPolicy, true, nil
}

func runProxy(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(proxyTLSDNSNames) > 0 && !proxyTLS {
		return fmt.Errorf("--tls-dns-name requires --tls")
	}

	enclavePolicyRaw := os.Getenv(enclavegithub.EnvPolicyJSON)
	enclaveCapabilityKey := os.Getenv(enclavegithub.EnvCapabilityKey)
	enclaveConfig, enclaveGuardPolicy, enclaveEnabled, err := resolveEnclaveProxyConfig(
		enclavePolicyRaw,
		enclaveCapabilityKey,
		proxyPolicy,
		proxyTrustedBots,
		proxyTrustedUsers,
	)
	if err != nil {
		return err
	}
	delegationConfig, delegationStatePath, err := resolveDelegationProxyConfig()
	if err != nil {
		return err
	}
	if delegationConfig != nil && enclaveEnabled {
		return fmt.Errorf("delegation and enclave proxy modes cannot be combined")
	}
	effectiveDIFCMode := proxyDIFCMode
	if enclaveEnabled {
		effectiveDIFCMode = difc.ModePropagate
	}

	logProxyCmd.Printf("Starting proxy: listen=%s, guard=%s, mode=%s, tls=%v, enclave=%v", proxyListen, proxyGuardWasm, effectiveDIFCMode, proxyTLS, enclaveEnabled)

	if _, err := difc.ParseEnforcementMode(effectiveDIFCMode); err != nil {
		return fmt.Errorf("invalid --guards-mode flag: %w", err)
	}

	// Initialize loggers
	logger.InitProxyLoggers(proxyLogDir)

	logger.LogInfo("startup", "MCPG Proxy starting: listen=%s, guard=%s, mode=%s, tls=%v, enclave=%v", proxyListen, proxyGuardWasm, effectiveDIFCMode, proxyTLS, enclaveEnabled)

	resolvedWasmCacheDir, cleanupWasmCache, err := setupWasmCompilationCache(ctx, cmd.Flags().Changed("wasm-cache-dir"), proxyWasmCacheDir, proxyLogDir)
	if err != nil {
		return err
	}
	defer cleanupWasmCache()
	logger.LogInfo("startup", "WASM compilation cache directory: %s", resolvedWasmCacheDir)

	// Initialize OpenTelemetry tracer provider for the proxy server.
	// When no endpoint is configured, a noop provider is used (zero overhead).
	var tracingCfg *config.TracingConfig
	if proxyOTLPEndpoint != "" {
		tracingCfg = &config.TracingConfig{
			Endpoint:    proxyOTLPEndpoint,
			ServiceName: proxyOTLPService,
			SampleRate:  &proxyOTLPSampleRate,
		}
	}
	// Provider enablement logging remains tied to explicit proxy flag configuration.
	_, cleanupTracing := setupCommandTracing(
		ctx,
		tracingCfg,
		"failed to initialize tracing provider: %v",
		logger.StartupWarn,
		logger.ShutdownWarn,
	)
	defer cleanupTracing()
	if tracingCfg != nil {
		logger.StartupInfo("OpenTelemetry tracing enabled for proxy: endpoint=%s, service=%s", proxyOTLPEndpoint, proxyOTLPService)
	} else {
		logger.StartupInfo("OpenTelemetry tracing disabled for proxy (no --otlp-endpoint configured)")
	}

	// Resolve GitHub token (optional — proxy forwards client auth by default)
	token := proxyToken
	if token == "" {
		token = envutil.LookupGitHubToken()
	}
	if token != "" {
		logger.LogInfo("startup", "GitHub token configured from flag/env")
	} else {
		if enclaveEnabled {
			return fmt.Errorf("GitHub token is required for enclave proxy mode")
		}
		logger.LogInfo("startup", "No fallback token — proxy will forward client Authorization headers")
	}

	// Resolve GitHub API URL: flag → env vars → default
	apiURL := proxyAPIURL
	if apiURL == "" {
		apiURL = envutil.DeriveGitHubAPIURL("")
	}
	if apiURL == "" {
		apiURL = proxy.DefaultGitHubAPIBase
	}
	logger.LogInfo("startup", "Upstream GitHub API URL: %s", apiURL)
	logProxyCmd.Printf("Resolved GitHub API URL: %s, explicit flag=%v", apiURL, proxyAPIURL != "")

	// Defense-in-depth: force repos="public" when running in a public repository.
	// This overrides the compiled policy to prevent agents from reading private
	// repos, even if the compiler misconfigured the allow-only scope.
	effectivePolicy := proxyPolicy
	if enclaveEnabled {
		effectivePolicy = enclaveGuardPolicy
	} else if effectivePolicy != "" {
		effectivePolicy = proxyForcePublicReposIfNeeded(ctx, effectivePolicy, token, apiURL)
	}

	// Create the proxy server
	logProxyCmd.Printf("Creating proxy server: guard=%s, hasPolicy=%v, mode=%s, trustedBots=%d, trustedUsers=%d",
		proxyGuardWasm, effectivePolicy != "", effectiveDIFCMode, len(proxyTrustedBots), len(proxyTrustedUsers))
	proxySrv, err := proxy.New(ctx, proxy.Config{
		WasmPath:     proxyGuardWasm,
		Policy:       effectivePolicy,
		GitHubToken:  token,
		GitHubAPIURL: apiURL,
		DIFCMode:     effectiveDIFCMode,
		TrustedBots:  proxyTrustedBots,
		TrustedUsers: proxyTrustedUsers,
		Enclave:      enclaveConfig,
		Delegation:   delegationConfig,
	})
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}
	logProxyCmd.Printf("Proxy server created successfully")

	var controlHTTPServer *http.Server
	controlListenerErrCh := make(chan error, 1)
	if delegationConfig != nil {
		controlListener, err := net.Listen("tcp", delegationConfig.ControlListenAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on private delegation control channel %s: %w", delegationConfig.ControlListenAddr, err)
		}
		controlHTTPServer = &http.Server{
			Handler: delegationConfigHandler(proxySrv),
		}
		go func() {
			if err := controlHTTPServer.Serve(controlListener); err != nil && err != http.ErrServerClosed {
				// A post-start failure of the private control listener
				// must not silently leave the data plane running while
				// AWF loses its only way to create, confirm, revoke, or
				// reconcile delegated identities: treat it as fatal to
				// the whole proxy process rather than merely logging it.
				logger.LogError("delegation", "Private delegation control channel exited unexpectedly, shutting down: %v", err)
				controlListenerErrCh <- err
				cancel()
			}
		}()
		defer func() {
			_ = controlHTTPServer.Shutdown(context.Background())
		}()
		logger.LogInfo("startup", "Private delegation control channel listening on %s", controlListener.Addr())
	}

	// Generate TLS certificates if requested
	var tlsCfg *proxy.TLSConfig
	if proxyTLS {
		tlsDir := proxyTLSDir
		if tlsDir == "" {
			tlsDir = filepath.Join(proxyLogDir, "proxy-tls")
		}
		logProxyCmd.Printf("Generating TLS certificates in: %s", tlsDir)
		tlsCfg, err = proxy.GenerateSelfSignedTLS(tlsDir, proxyTLSDNSNames...)
		if err != nil {
			return fmt.Errorf("failed to generate TLS certificates: %w", err)
		}
		if err := httputil.ConfigureTLSTrustEnvironment(tlsCfg.CACertPath); err != nil {
			return err
		}
		logger.LogInfo("startup", "TLS certificates generated: ca=%s", tlsCfg.CACertPath)
	}

	// Create the HTTP server
	logProxyCmd.Printf("Creating HTTP server: addr=%s, tls=%v", proxyListen, tlsCfg != nil)
	httpServer := &http.Server{
		Addr:    proxyListen,
		Handler: proxySrv.Handler(),
	}
	if tlsCfg != nil {
		logProxyCmd.Printf("Applying TLS configuration to HTTP server")
		httpServer.TLSConfig = tlsCfg.Config
	}

	err = serveAndWait(
		ctx,
		cancel,
		httpServer,
		shutdownTimeout,
		func() {
			logger.LogInfoToMarkdown("shutdown", "Shutting down proxy...")
		},
		func() error {
			listener, err := net.Listen("tcp", proxyListen)
			if err != nil {
				return fmt.Errorf("failed to listen on %s: %w", proxyListen, err)
			}

			if tlsCfg != nil {
				listener = tls.NewListener(listener, tlsCfg.Config)
			}

			actualAddr := listener.Addr().String()
			scheme := "http"
			if tlsCfg != nil {
				scheme = "https"
			}

			logger.StartupInfo("Proxy listening on %s://%s", scheme, actualAddr)

			// Print connection info
			stderr := cmd.ErrOrStderr()
			fmt.Fprintf(stderr, "\nMCPG GitHub API Proxy\n")
			fmt.Fprintf(stderr, "  Listening: %s://%s\n", scheme, actualAddr)
			fmt.Fprintf(stderr, "  Upstream:  %s\n", apiURL)
			fmt.Fprintf(stderr, "  Mode:      %s\n", proxyDIFCMode)
			fmt.Fprintf(stderr, "  Guard:     %s\n", proxyGuardWasm)
			if tlsCfg != nil {
				fmt.Fprintf(stderr, "  CA cert:   %s\n", tlsCfg.CACertPath)
				fmt.Fprintf(stderr, "\nConnect with:\n")
				fmt.Fprintf(stderr, "  export GH_HOST=%s\n", util.ClientAddr(actualAddr))
				fmt.Fprintf(stderr, "  export NODE_EXTRA_CA_CERTS=%s\n", tlsCfg.CACertPath)
				fmt.Fprintf(stderr, "  export SSL_CERT_FILE=%s\n", tlsCfg.CACertPath)
				fmt.Fprintf(stderr, "  export GIT_SSL_CAINFO=%s\n", tlsCfg.CACertPath)
				fmt.Fprintf(stderr, "  gh issue list -R org/repo\n\n")
			} else {
				fmt.Fprintf(stderr, "\nConnect with:\n")
				fmt.Fprintf(stderr, "  curl http://%s/repos/org/repo/issues\n\n", actualAddr)
			}

			return httpServer.Serve(listener)
		},
	)

	// A control-listener failure triggers cancel(), which typically makes the
	// main serve loop above return its own (e.g. context-canceled) error first.
	// Always drain the channel and prioritize the control-listener error as the
	// real root cause when present, regardless of what the serve loop returned.
	select {
	case controlErr := <-controlListenerErrCh:
		err = fmt.Errorf("private delegation control channel failed: %w", controlErr)
	default:
	}
	if err != nil {
		logger.LogError("shutdown", "Proxy server exited with error: %v", err)
		return err
	}
	if delegationConfig != nil {
		if err := delegationConfig.Store.SaveState(delegationStatePath); err != nil {
			return fmt.Errorf("failed to persist delegation state: %w", err)
		}
	}

	return nil
}

func delegationConfigHandler(server *proxy.Server) http.Handler {
	return server.ControlHandler()
}

// proxyForcePublicReposIfNeeded checks if GITHUB_REPOSITORY is public and, if so,
// overrides the allow-only policy's repos field to "public". This prevents agents
// in public-repo workflows from reading private repos through the proxy.
//
// Skipped when:
//   - --force-public-repos=false (or MCP_GATEWAY_FORCE_PUBLIC_REPOS=false)
//   - GITHUB_REPOSITORY is not set
//   - No GitHub token is available
//   - The API call fails (fail-open)
//   - The repository is not public
func proxyForcePublicReposIfNeeded(ctx context.Context, policyJSON, token, apiURL string) string {
	if !proxyForcePublicRepo {
		logger.LogInfo("difc", "forcePublicRepos: disabled")
		return policyJSON
	}

	nwo := os.Getenv("GITHUB_REPOSITORY")
	if nwo == "" {
		logger.LogInfo("difc", "forcePublicRepos: GITHUB_REPOSITORY not set — skipping")
		return policyJSON
	}

	authToken := token
	if authToken == "" {
		authToken = envutil.LookupGitHubToken()
	}
	if authToken == "" {
		logger.LogInfo("difc", "forcePublicRepos: no GitHub token available — skipping")
		return policyJSON
	}

	vis, err := githubhttp.FetchRepoVisibility(ctx, apiURL, nwo, "token "+authToken)
	if err != nil {
		logger.LogWarn("difc", "forcePublicRepos: failed to determine visibility for %s (fail-open): %v", nwo, err)
		return policyJSON
	}

	if vis != githubhttp.RepoVisibilityPublic {
		logger.LogInfo("difc", "forcePublicRepos: repo %s is %s — no override needed", nwo, vis)
		return policyJSON
	}

	// Repository is public — override policy to repos="public"
	var policyMap map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policyMap); err != nil {
		logger.LogWarn("difc", "forcePublicRepos: failed to parse policy JSON (using original): %v", err)
		return policyJSON
	}
	if policyMap == nil {
		logger.LogWarn("difc", "forcePublicRepos: policy JSON decoded to null (using original)")
		return policyJSON
	}

	// Find the allow-only section (canonical or legacy key)
	var allowOnly map[string]interface{}
	if ao, ok := policyMap["allow-only"]; ok {
		allowOnly, _ = ao.(map[string]interface{})
	} else if ao, ok := policyMap["allowonly"]; ok {
		allowOnly, _ = ao.(map[string]interface{})
	}

	if allowOnly == nil {
		policyMap["allow-only"] = map[string]interface{}{
			"repos":         "public",
			"min-integrity": "none",
		}
	} else {
		allowOnly["repos"] = "public"
	}

	overridden, err := json.Marshal(policyMap)
	if err != nil {
		logger.LogWarn("difc", "forcePublicRepos: failed to marshal overridden policy (using original): %v", err)
		return policyJSON
	}

	logger.LogWarn("difc", "FORCED REPOS=PUBLIC: workflow repo %s is public — overriding proxy allow-only scope to prevent private data reads", nwo)
	return string(overridden)
}
