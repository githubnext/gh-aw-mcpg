// Package proxy implements a filtering HTTP proxy for the GitHub API.
// It intercepts gh CLI requests (via GH_HOST redirect) and applies
// the same DIFC enforcement pipeline as the MCP gateway, reusing the
// guard WASM module, evaluator, and agent registry.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/github/gh-aw-mcpg/internal/config"
	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/enclavegithub"
	"github.com/github/gh-aw-mcpg/internal/githubhttp"
	"github.com/github/gh-aw-mcpg/internal/guard"
	"github.com/github/gh-aw-mcpg/internal/httputil"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/mcp"
	"github.com/github/gh-aw-mcpg/internal/sanitize"
	"github.com/github/gh-aw-mcpg/internal/tracing"
	"github.com/github/gh-aw-mcpg/internal/util"
)

var artifactZipDownloadPathPattern = regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/artifacts/\d+/zip$`)

var logProxy = logger.ForFile()

const (
	// DefaultGitHubAPIBase is the upstream GitHub API URL.
	DefaultGitHubAPIBase = "https://api.github.com"

	// ghHostPathPrefix is the /api/v3/ prefix that gh adds when using GH_HOST.
	ghHostPathPrefix = "/api/v3"

	proxyAgentID = "proxy"
)

// Server is a filtering HTTP forward proxy for the GitHub REST/GraphQL API.
// It loads the same WASM guard used by the MCP gateway and runs the 6-phase
// DIFC pipeline on every proxied response.
type Server struct {
	guard guard.Guard
	difc.DIFCComponents

	githubToken  string
	githubAPIURL string // upstream base URL (no trailing slash)

	httpClient *http.Client

	// guardInitialized tracks whether LabelAgent has been called
	guardInitialized bool

	enclave    *enclaveState
	delegation *delegationState
}

// EnclaveConfig enables the fail-closed issues-read-v1 proxy profile.
type EnclaveConfig struct {
	Policy   *enclavegithub.Policy
	Verifier *enclavegithub.Verifier
}

// Config holds the configuration for creating a proxy Server.
type Config struct {
	// WasmPath is the file path to the guard WASM module.
	WasmPath string

	// Policy is the guard policy JSON (e.g. {"allow-only":{...}}).
	Policy string

	// GitHubToken is a fallback token for upstream GitHub API requests.
	// When empty, the proxy forwards the client's Authorization header instead.
	GitHubToken string

	// GitHubAPIURL overrides the upstream API base URL (default: https://api.github.com).
	GitHubAPIURL string

	// DIFCMode is the enforcement mode (strict, filter, propagate).
	DIFCMode string

	// TrustedBots is an optional list of additional trusted bot usernames.
	// These are passed to the guard alongside the policy during LabelAgent
	// initialization, extending the guard's built-in trusted bot list
	// (e.g. dependabot[bot], github-actions[bot]).
	TrustedBots []string

	// TrustedUsers is an optional list of GitHub usernames to elevate to approved
	// (writer) integrity, regardless of their author_association. These are injected
	// into the allow-only policy's trusted-users field during LabelAgent initialization.
	TrustedUsers []string

	// Enclave enables invocation-capability enforcement for issues-read-v1.
	Enclave *EnclaveConfig

	// Delegation enables runtime AWF-controlled repository-read identities.
	Delegation *DelegationConfig
}

// New creates a new proxy Server from the given Config.
func New(ctx context.Context, cfg Config) (*Server, error) {
	logProxy.Printf("Creating proxy server: wasmPath=%s, apiURL=%s, difcMode=%s, hasToken=%v, hasPolicy=%v",
		cfg.WasmPath, cfg.GitHubAPIURL, cfg.DIFCMode, cfg.GitHubToken != "", cfg.Policy != "")

	if cfg.WasmPath == "" {
		return nil, fmt.Errorf("guard WASM path is required")
	}
	if cfg.Enclave != nil && cfg.Delegation != nil {
		return nil, fmt.Errorf("enclave and delegation proxy modes cannot be combined")
	}
	delegation, err := newDelegationState(cfg.Delegation)
	if err != nil {
		return nil, err
	}
	if delegation != nil && cfg.GitHubToken == "" {
		return nil, fmt.Errorf("GitHub token is required for delegation proxy mode")
	}
	if cfg.Enclave != nil {
		if cfg.Enclave.Policy == nil || cfg.Enclave.Verifier == nil {
			return nil, fmt.Errorf("enclave policy and verifier are required")
		}
		if err := cfg.Enclave.Policy.Validate(); err != nil {
			return nil, fmt.Errorf("invalid enclave policy: %w", err)
		}
		if cfg.GitHubToken == "" {
			return nil, fmt.Errorf("GitHub token is required for enclave proxy mode")
		}
	}

	// Enclave and delegation profiles admit private repositories that are
	// chosen at runtime by the controller, so the selector, its request paths,
	// and the run/entry/invocation identifiers bound to it are all secrets.
	// Enable process-wide redaction before anything else in the request path
	// can log, so a missed call site cannot disclose them under DEBUG=*.
	if cfg.Enclave != nil || delegation != nil {
		sanitize.EnablePrivateSelectorRedaction()
	}

	apiURL := cfg.GitHubAPIURL
	if apiURL == "" {
		apiURL = DefaultGitHubAPIBase
	}
	apiURL = strings.TrimRight(apiURL, "/")
	logProxy.Printf("Using upstream GitHub API URL: %s", apiURL)
	// Initialize DIFC components (defaults to filter mode for the proxy).
	// NewComponents returns any parse error so we can warn without parsing twice.
	difcComponents, difcParseErr := difc.NewComponents(cfg.DIFCMode, difc.EnforcementFilter)
	if difcParseErr != nil {
		logger.LogWarn("startup", "invalid DIFC mode %q, defaulting to filter: %v", cfg.DIFCMode, difcParseErr)
	}
	logProxy.Printf("Enforcement mode resolved: %s", difcComponents.Mode)

	// Load the WASM guard
	logProxy.Printf("Loading WASM guard from: %s", cfg.WasmPath)
	g, err := guard.NewWasmGuard(ctx, "github", cfg.WasmPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load WASM guard from %s: %w", cfg.WasmPath, err)
	}
	logProxy.Printf("WASM guard loaded successfully")

	s := &Server{
		guard:          g,
		DIFCComponents: difcComponents,
		githubToken:    cfg.GitHubToken,
		githubAPIURL:   apiURL,
		delegation:     delegation,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: httputil.NewClientTLSConfig(),
			},
		},
	}
	if cfg.Enclave != nil {
		s.enclave = newEnclaveState(cfg.Enclave.Policy, cfg.Enclave.Verifier)
		s.httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Initialize guard policy (LabelAgent)
	if cfg.Policy != "" {
		logProxy.Printf("Initializing guard policy from config")
		if err := s.initGuardPolicy(ctx, cfg.Policy, cfg.TrustedBots, cfg.TrustedUsers); err != nil {
			return nil, fmt.Errorf("failed to initialize guard policy: %w", err)
		}
	} else {
		logProxy.Printf("No guard policy configured, running without policy enforcement")
	}
	if s.delegation != nil {
		if !s.guardInitialized {
			return nil, fmt.Errorf("guard policy is required for delegation proxy mode")
		}
		initialLabels, ok := s.AgentRegistry.Get(proxyAgentID)
		if !ok {
			return nil, fmt.Errorf("delegation guard did not initialize agent labels")
		}
		s.AgentRegistry.SetDefaultLabels(nil, initialLabels.GetIntegrityTags())
		s.Mode = difc.EnforcementPropagate
		s.Evaluator.SetMode(difc.EnforcementPropagate)
	}
	if s.enclave != nil {
		if !s.guardInitialized {
			return nil, fmt.Errorf("guard policy is required for enclave proxy mode")
		}
		initialLabels, ok := s.AgentRegistry.Get(proxyAgentID)
		if !ok {
			return nil, fmt.Errorf("enclave guard did not initialize agent labels")
		}
		s.AgentRegistry.SetDefaultLabels(nil, initialLabels.GetIntegrityTags())
		s.Mode = difc.EnforcementPropagate
		s.Evaluator.SetMode(difc.EnforcementPropagate)
	}

	logProxy.Printf("Proxy server created successfully: mode=%s", difcComponents.Mode)
	return s, nil
}

// initGuardPolicy calls LabelAgent with the provided policy JSON, optional trusted bots, and optional trusted users.
func (s *Server) initGuardPolicy(ctx context.Context, policyJSON string, trustedBots []string, trustedUsers []string) error {
	logProxy.Printf("Initializing guard policy: policyJSON_len=%d, trustedBots=%d, trustedUsers=%d", len(policyJSON), len(trustedBots), len(trustedUsers))

	var policy interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return fmt.Errorf("invalid policy JSON: %w", err)
	}

	// Validate via the canonical helper so proxy.go stays in sync with any
	// future changes to GuardPolicy.UnmarshalJSON or ValidateGuardPolicy.
	parsedPolicy, err := config.ParseGuardPolicyJSON(policyJSON)
	if err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}
	if parsedPolicy.WriteSink != nil {
		return fmt.Errorf("policy validation failed: write-sink policies are not supported for guard initialization; expected top-level allow-only/allowonly policy")
	}

	// Normalize legacy top-level policy keys before building the payload so
	// trusted user injection works for both canonical and legacy input forms.
	if policyMap, ok := policy.(map[string]interface{}); ok {
		if _, hasCanonical := policyMap["allow-only"]; !hasCanonical {
			if legacy, hasLegacy := policyMap["allowonly"]; hasLegacy {
				policyMap["allow-only"] = legacy
			}
		}
	}

	logProxy.Printf("Calling LabelAgent to initialize agent labels from guard")
	backend := &restBackendCaller{server: s}
	newMode, result, err := guard.RunLabelAgentInit(
		ctx,
		s.guard,
		policy,
		trustedBots,
		trustedUsers,
		backend,
		s.Capabilities,
		s.AgentRegistry,
		proxyAgentID,
		s.Mode,
	)
	if err != nil {
		return err
	}
	logProxy.Printf("Agent labels applied: secrecy=%v, integrity=%v", result.Agent.Secrecy, result.Agent.Integrity)

	if result.DIFCMode != "" {
		logProxy.Printf("Enforcement mode overridden by guard response: %s → %s", s.Mode, newMode)
		s.Mode = newMode
		s.Evaluator.SetMode(newMode)
	}

	s.guardInitialized = true
	logProxy.Printf("Guard initialized: mode=%s, secrecy=%v, integrity=%v",
		s.Mode, result.Agent.Secrecy, result.Agent.Integrity)

	return nil
}

// Handler returns an http.Handler for the proxy server.
// Every request is wrapped with an OTEL "proxy.request" span so the full
// proxy lifecycle (DIFC pipeline + GitHub API round-trip) appears in traces.
func (s *Server) Handler() http.Handler {
	handler := &proxyHandler{
		server:       s,
		CachedTracer: tracing.CachedTracer{Tracer: tracing.Tracer()},
	}
	// Delegation mode admits private repositories the same way enclave mode
	// does, so the request path is invocation-scoped secret material and must
	// not be recorded as a span attribute either.
	if s.enclave != nil || s.delegation != nil {
		return tracing.WrapHTTPHandlerWithoutPath(handler, "proxy.request")
	}
	return tracing.WrapHTTPHandler(handler, "proxy.request")
}

// sensitiveLogging reports whether this server admits private repositories
// chosen at runtime (enclave or delegation mode). In those modes repository
// selectors, request paths, and the run/entry/invocation identifiers bound to
// them are secret and must only ever be logged as stable hashes.
func (s *Server) sensitiveLogging() bool {
	return s.enclave != nil || s.delegation != nil
}

// logSafePath renders an upstream API path for logs, error strings, and span
// attributes. In enclave and delegation modes the path embeds a private
// repository selector plus issue/PR/ref identifiers, so it is replaced with a
// stable hash that still correlates across log lines.
func (s *Server) logSafePath(path string) string {
	if !s.sensitiveLogging() {
		return path
	}
	return util.HashForLog(path, 16, "path:")
}

// restBackendCaller translates guard CallTool requests into GitHub REST API
// calls, enabling backend enrichment (author_association, repo visibility, etc.)
// that the WASM guard needs for accurate integrity labeling.
type restBackendCaller struct {
	server     *Server
	clientAuth string
}

func (r *restBackendCaller) CallTool(ctx context.Context, toolName string, args interface{}) (interface{}, error) {
	argsMap, ok := args.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected args type: %T", args)
	}

	// Enclave and delegation modes admit only private, dynamically-discovered
	// repository paths; never write raw path/owner/repo selectors to logs in
	// those modes, only their non-reversible hashes.
	sensitive := r.server.sensitiveLogging()

	var (
		apiPath                                 string
		collabOwner, collabRepo, collabUsername string
	)
	switch toolName {
	case "pull_request_read":
		owner, repo, number, err := extractOwnerRepoNumber(argsMap, "owner", "repo", "pullNumber", toolName)
		if err != nil {
			return nil, err
		}
		apiPath = fmt.Sprintf("/repos/%s/%s/pulls/%s", owner, repo, number)

	case "issue_read":
		owner, repo, number, err := extractOwnerRepoNumber(argsMap, "owner", "repo", "issue_number", toolName)
		if err != nil {
			return nil, err
		}
		apiPath = fmt.Sprintf("/repos/%s/%s/issues/%s", owner, repo, number)

	case "search_repositories":
		query, _ := argsMap["query"].(string)
		if query == "" {
			return nil, fmt.Errorf("search_repositories: missing query")
		}
		if r.server.enclave != nil {
			repoQuery, ok := strings.CutPrefix(query, "repo:")
			repo, valid := enclavegithub.NormalizeRepository(repoQuery)
			if !ok || !valid {
				return nil, fmt.Errorf("search_repositories: enclave lookup must use an exact repository")
			}
			apiPath = "/repos/" + repo
		} else {
			perPage := "10"
			if pp, ok := argsMap["perPage"].(float64); ok {
				perPage = fmt.Sprintf("%d", int(pp))
			}
			apiPath = fmt.Sprintf("/search/repositories?q=%s&per_page=%s", url.QueryEscape(query), perPage)
		}

	case "get_collaborator_permission":
		var parseErr error
		collabOwner, collabRepo, collabUsername, parseErr = githubhttp.ParseCollaboratorPermissionArgs(argsMap)
		if parseErr != nil {
			if sensitive {
				logProxy.Printf("restBackendCaller: get_collaborator_permission missing args")
			} else {
				logProxy.Printf("restBackendCaller: get_collaborator_permission missing args (owner=%q repo=%q username=%q)", collabOwner, collabRepo, collabUsername)
			}
			return nil, parseErr
		}
		apiPath = fmt.Sprintf("/repos/%s/%s/collaborators/%s/permission", collabOwner, collabRepo, collabUsername)

	default:
		logProxy.Printf("restBackendCaller: unsupported tool %s", toolName)
		return nil, fmt.Errorf("unsupported tool: %s", toolName)
	}

	logProxy.Printf("restBackendCaller: %s → GET %s", toolName, r.server.logSafePath(apiPath))

	// Use the server's configured token for enrichment calls rather than the
	// client's auth header. Enrichment needs org-level visibility (e.g. to get
	// correct author_association) which the client's GITHUB_TOKEN may lack.
	enrichmentAuth := ""
	if r.server.githubToken != "" {
		enrichmentAuth = "token " + r.server.githubToken
	} else if r.clientAuth != "" {
		enrichmentAuth = r.clientAuth
	}
	// For get_collaborator_permission, reuse shared REST call helper.
	if toolName == "get_collaborator_permission" {
		result, err := githubhttp.FetchCollaboratorPermission(
			ctx,
			collabOwner,
			collabRepo,
			collabUsername,
			func(ctx context.Context, collabAPIPath string) (*http.Response, error) {
				resp, err := r.server.forwardToGitHub(ctx, "GET", collabAPIPath, nil, "", enrichmentAuth)
				if err != nil {
					return nil, fmt.Errorf("REST call failed: %w", err)
				}
				return resp, nil
			},
			logProxy.Printf,
			sensitive,
		)
		if err != nil {
			logProxy.Printf("restBackendCaller: %s returned error: %v", toolName, err)
			return nil, err
		}
		return result, nil
	}

	resp, err := r.server.forwardToGitHub(ctx, "GET", apiPath, nil, "", enrichmentAuth)
	if err != nil {
		return nil, fmt.Errorf("REST call failed: %w", err)
	}
	body, err := httputil.ReadResponseBody(resp, "GitHub API")
	if err != nil {
		logProxy.Printf("restBackendCaller: %s returned error: %v", toolName, err)
		return nil, err
	}

	// Wrap in MCP response format: {content: [{type: "text", text: "..."}]}
	return mcp.BuildMCPTextResponse(string(body)), nil
}

// upstreamHost returns the hostname of the upstream GitHub API URL.
// It is used to populate the server.address OTel attribute on the
// proxy.backend.forward span.
func (s *Server) upstreamHost() string {
	u, err := url.Parse(s.githubAPIURL)
	if err == nil && u.Host != "" {
		return u.Hostname()
	}

	// Handle scheme-less config values like "api.github.com" or "api.github.com/api/v3".
	u, err = url.Parse("https://" + strings.TrimLeft(s.githubAPIURL, "/"))
	if err == nil && u.Host != "" {
		return u.Hostname()
	}

	host, _, _ := strings.Cut(strings.TrimLeft(s.githubAPIURL, "/"), "/")
	return host
}

// forwardToGitHub sends a request to the upstream GitHub API.
// clientAuth is the Authorization header from the inbound client request;
// if non-empty it is forwarded as-is, otherwise the configured fallback token is used.
func (s *Server) forwardToGitHub(ctx context.Context, method, path string, body io.Reader, contentType string, clientAuth string) (*http.Response, error) {
	url := s.githubAPIURL + path
	pathOnly, query, hasQuery := strings.Cut(path, "?")
	if IsGraphQLPath(pathOnly) {
		var graphqlURL string
		if strings.HasSuffix(s.githubAPIURL, "/api/v3") {
			// GHES: strip /api/v3, GraphQL lives at /api/graphql
			graphqlURL = strings.TrimSuffix(s.githubAPIURL, "/api/v3") + "/api/graphql"
		} else {
			// github.com and GHEC data residency (api.<tenant>.ghe.com):
			// GraphQL lives at /graphql
			graphqlURL = s.githubAPIURL + "/graphql"
		}
		url = graphqlURL
		if hasQuery {
			url += "?" + query
		}
	}
	if s.enclave != nil {
		logProxy.Printf("forwarding enclave request: %s", method)
	} else if s.delegation != nil {
		logProxy.Printf("forwarding delegated request: %s", method)
	} else {
		logProxy.Printf("forwarding %s %s → %s", method, path, url)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Enclave mode always replaces the invocation capability with mcpg's token.
	var authHeader string
	if s.enclave != nil || s.delegation != nil {
		authHeader = "token " + s.githubToken
	} else if clientAuth != "" {
		authHeader = clientAuth
	} else if s.githubToken != "" {
		authHeader = "token " + s.githubToken
	}
	githubhttp.ApplyGitHubAPIHeaders(req, authHeader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method == http.MethodGet && artifactZipDownloadPathPattern.MatchString(pathOnly) {
		return doWithoutFollowingRedirects(s.httpClient, req)
	}
	return s.httpClient.Do(req)
}

func doWithoutFollowingRedirects(client *http.Client, req *http.Request) (*http.Response, error) {
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return noRedirectClient.Do(req)
}
