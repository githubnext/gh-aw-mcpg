package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/envutil"
	"github.com/github/gh-aw-mcpg/internal/githubhttp"
	"github.com/github/gh-aw-mcpg/internal/guard"
	"github.com/github/gh-aw-mcpg/internal/launcher"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/mcp"
	"github.com/github/gh-aw-mcpg/internal/tracing"
	"github.com/github/gh-aw-mcpg/internal/util"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// executeBackendRequest sends a JSON-RPC request to a backend server and unmarshals the
// result into T. It centralizes: GetOrLaunchForSession → SendRequestWithServerID →
// error check → unmarshal.
func executeBackendRequest[T any](ctx context.Context, l *launcher.Launcher, serverID, sessionID, method string, params map[string]interface{}) (T, error) {
	var zero T
	conn, err := launcher.GetOrLaunchForSession(l, serverID, sessionID)
	if err != nil {
		return zero, fmt.Errorf("failed to connect to backend %s: %w", serverID, err)
	}

	response, err := conn.SendRequestWithServerID(ctx, method, params, serverID)
	if err != nil {
		return zero, err
	}

	if response.Error != nil {
		logUnified.Printf("executeBackendRequest: backend error: serverID=%s, method=%s, code=%d", serverID, method, response.Error.Code)
		return zero, fmt.Errorf("backend error server=%s method=%s: code=%d, message=%s", serverID, method, response.Error.Code, response.Error.Message)
	}

	var result T
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return zero, fmt.Errorf("failed to parse %s result: %w", method, err)
	}

	return result, nil
}

// executeBackendToolCall executes a backend MCP tool call and returns the raw result.
// This helper consolidates the common pattern of:
// 1. Get or launch backend connection
// 2. Send tools/call request
// 3. Check for backend error
// 4. Unmarshal and return result
//
// Callers are responsible for adapting the result to their specific return types
// and wrapping errors as needed.
func executeBackendToolCall(ctx context.Context, l *launcher.Launcher, serverID, sessionID, toolName string, args interface{}) (interface{}, error) {
	logUnified.Printf("executeBackendToolCall: serverID=%s, toolName=%s", serverID, toolName)
	return executeBackendRequest[interface{}](ctx, l, serverID, sessionID, "tools/call", map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	})
}

var executeBackendToolCallFunc = executeBackendToolCall

// guardBackendCaller implements guard.BackendCaller for guards to query backend metadata
type guardBackendCaller struct {
	server   *UnifiedServer
	serverID string
	ctx      context.Context
}

func (g *guardBackendCaller) CallTool(ctx context.Context, toolName string, args interface{}) (interface{}, error) {
	// Intercept synthetic tools that require direct REST API calls
	if toolName == "get_collaborator_permission" {
		return g.callCollaboratorPermission(ctx, args)
	}

	// Make a read-only call to the backend for metadata
	// This bypasses DIFC checks since it's internal to the guard
	logUnified.Printf("[DIFC] Guard calling backend %s tool %s for metadata", g.serverID, toolName)

	sessionID := SessionIDFromContext(g.ctx)

	return executeBackendToolCallFunc(g.ctx, g.server.launcher, g.serverID, sessionID, toolName, args)
}

// callCollaboratorPermission makes a direct REST API call to GitHub to get a user's
// effective permission level for a repository. This is more accurate than author_association
// because it includes inherited org permissions.
func (g *guardBackendCaller) callCollaboratorPermission(ctx context.Context, args interface{}) (interface{}, error) {
	argsMap, ok := args.(map[string]interface{})
	if !ok {
		logUnified.Printf("get_collaborator_permission: unexpected args type %T, expected map[string]interface{}", args)
		return nil, fmt.Errorf("get_collaborator_permission: unexpected args type: %T", args)
	}

	owner, repo, username, err := githubhttp.ParseCollaboratorPermissionArgs(argsMap)
	if err != nil {
		logUnified.Printf("get_collaborator_permission: missing required args (owner=%q repo=%q username=%q)", owner, repo, username)
		return nil, err
	}

	token := envutil.LookupGitHubToken()
	if token == "" {
		logUnified.Printf("get_collaborator_permission: no GitHub token available for %s/%s user %s, skipping", owner, repo, username)
		return nil, fmt.Errorf("get_collaborator_permission: no GitHub token available")
	}

	apiURL := envutil.DeriveGitHubAPIURL(envutil.DefaultGitHubAPIBaseURL)
	result, err := githubhttp.FetchCollaboratorPermission(
		ctx,
		owner,
		repo,
		username,
		func(ctx context.Context, apiPath string) (*http.Response, error) {
			logUnified.Printf("get_collaborator_permission: GET %s (for %s/%s user %s)", apiPath, owner, repo, username)
			resp, err := githubhttp.DoGitHubGET(ctx, apiURL, apiPath, "token "+token)
			if err != nil {
				logUnified.Printf("get_collaborator_permission: REST call failed for %s/%s user %s: %v", owner, repo, username, err)
				return nil, fmt.Errorf("REST call failed: %w", err)
			}
			return resp, nil
		},
		logUnified.Printf,
		// This is the launcher-backed unified/routed server, which has no
		// enclave or delegation mode (those only exist in internal/proxy.Server);
		// there is no private-repository selector to redact here.
		false,
	)
	if err != nil {
		logUnified.Printf("get_collaborator_permission: request failed for %s/%s user %s: %v", owner, repo, username, err)
		return nil, fmt.Errorf("get_collaborator_permission: %w", err)
	}
	return result, nil
}

// getCircuitBreaker returns the circuit breaker for serverID, creating one with
// defaults if none exists (e.g., when called from tests that bypass NewUnified).
func (us *UnifiedServer) getCircuitBreaker(serverID string) *circuitBreaker {
	if us.circuitBreakers == nil {
		us.circuitBreakers = make(map[string]*circuitBreaker)
	}
	if cb, ok := us.circuitBreakers[serverID]; ok {
		return cb
	}
	logUnified.Printf("Creating new circuit breaker for serverID=%s (threshold=%d, cooldown=%v)", serverID, DefaultRateLimitThreshold, DefaultRateLimitCooldown)
	cb := newCircuitBreaker(serverID, DefaultRateLimitThreshold, DefaultRateLimitCooldown)
	us.circuitBreakers[serverID] = cb
	return cb
}

// isToolAllowed reports whether toolName is permitted by the server's configured
// allowed-tools list. When no list is configured (empty), all tools are allowed.
// Uses the pre-computed allowedToolSets map for O(1) lookup.
func (us *UnifiedServer) isToolAllowed(serverID, toolName string) bool {
	set, ok := us.allowedToolSets[serverID]
	if !ok || set == nil {
		return true
	}
	allowed := set[toolName]
	if !allowed {
		logUnified.Printf("isToolAllowed: tool blocked by allowlist: serverID=%s, toolName=%s", serverID, toolName)
	}
	return allowed
}

// callBackendTool calls a tool on a backend server with DIFC enforcement
func (us *UnifiedServer) callBackendTool(ctx context.Context, serverID, toolName string, args interface{}) (*sdk.CallToolResult, interface{}, error) {
	// Note: Session validation happens at the tool registration level via closures
	// The closure captures the request and validates before calling this method
	logUnified.Printf("callBackendTool: serverID=%s, toolName=%s, args=%+v", serverID, toolName, args)

	// Apply the configured tool timeout as a context deadline so backend calls
	// (including HTTP backends) are bounded by toolTimeout rather than hanging
	// indefinitely.  This is the primary enforcement point for the gateway's
	// tool execution budget.
	// Per-server tool_timeout takes precedence over the global gateway.tool_timeout.
	toolTimeout := 0
	if us.cfg != nil {
		if serverCfg, ok := us.cfg.Servers[serverID]; ok && serverCfg != nil && serverCfg.ToolTimeout > 0 {
			toolTimeout = serverCfg.ToolTimeout
			logUnified.Printf("callBackendTool: using per-server tool_timeout=%d for serverID=%s", toolTimeout, serverID)
		} else if us.cfg.Gateway != nil && us.cfg.Gateway.ToolTimeout > 0 {
			toolTimeout = us.cfg.Gateway.ToolTimeout
		}
	}
	if toolTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(toolTimeout)*time.Second)
		defer cancel()
	}

	// Start an OTEL span for the full tool call lifecycle (spans all phases 0–6)
	// Attribute names follow the OpenTelemetry gen_ai semantic conventions
	ctx, toolSpan := tracing.StartToolCallSpan(ctx, us.GetTracer(), serverID, toolName)
	// httpStatusCode tracks the conceptual HTTP status of the proxied response (spec §4.1.3.6).
	// It starts at 200 and is updated to 500 (error), 403 (access denied), or 429 (budget
	// exhaustion) before each exit.
	httpStatusCode := 200
	defer func() {
		toolSpan.SetAttributes(tracing.MCPResponseStatus.Int(httpStatusCode))
		toolSpan.End()
	}()

	sessionID := us.getSessionID(ctx)
	// Propagate a redacted, stable session attribution to the tool call span so it
	// is queryable on child spans without exposing the raw authenticated identity.
	if toolSpan.IsRecording() {
		toolSpan.SetAttributes(tracing.GenAIConversationID.String(util.HashIdentifierForLog(sessionID)))
	}

	// **Per-agent policy enforcement**: reject calls to servers/tools the
	// authenticated agent is not permitted to use. This is defense-in-depth
	// alongside the per-agent tool-visibility filtering applied at session
	// establishment (createAgentFilteredServer / createAgentFilteredUnifiedServer).
	if us.agentPoliciesEnforced() {
		agentIdentity := guard.GetAgentIDFromContext(ctx)
		if !us.agentCanUseTool(agentIdentity, serverID, toolName) {
			logger.LogWarn("client", "tools/call denied by per-agent policy: agent=%s tool=%q server=%s",
				util.HashIdentifierForLog(agentIdentity), toolName, serverID)
			httpStatusCode = 403
			deniedErr := fmt.Errorf("tool %q on server %q is not permitted for this agent", toolName, serverID)
			tracing.RecordSpanError(toolSpan, deniedErr, "agent policy denied")
			return mcp.NewErrorCallToolResult(deniedErr)
		}

	}

	// Stateful guards keep label_agent policy context in their module memory.
	// Multi-agent gateways therefore use an isolated instance per agent/server.
	g, err := us.guardForSession(ctx, sessionID, serverID)
	if err != nil {
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("failed to create isolated guard session: %w", err))
	}

	// **Allowed-tools enforcement**: reject calls for tools not in the configured list.
	// This is a server-side guard so agents cannot bypass client-side --allowed-tools
	// filters by sending raw tools/call requests directly to the gateway.
	if !us.isToolAllowed(serverID, toolName) {
		logger.LogWarn("client", "tools/call denied: tool=%q not in allowed-tools for server=%s",
			toolName, serverID)
		httpStatusCode = 403
		deniedErr := fmt.Errorf("tool %q is not in the allowed-tools list for this server", toolName)
		tracing.RecordSpanError(toolSpan, deniedErr, "tool not allowed")
		return mcp.NewErrorCallToolResult(deniedErr)
	}

	// Create backend caller for the guard
	backendCaller := &guardBackendCaller{
		server:   us,
		serverID: serverID,
		ctx:      ctx,
	}

	// Initialize policy-driven guard session state (label_agent) before first guarded call.
	enforcementMode, err := us.ensureGuardInitialized(ctx, sessionID, serverID, g, backendCaller)
	if err != nil {
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("guard session initialization failed: %w", err))
	}
	if err := us.enforceToolCallLimit(sessionID, serverID, toolName); err != nil {
		httpStatusCode = 429
		tracing.RecordSpanError(toolSpan, err, "tool call limit reached")
		return mcp.NewErrorCallToolResult(err)
	}

	requestEvaluator := difc.NewEvaluatorWithMode(enforcementMode)

	// **Phases 0–2: Get agent labels, label resource, coarse access check**
	agentID := guard.GetAgentIDFromContext(ctx)
	pipelineIn := guard.PipelineInput{
		AgentID:         agentID,
		ToolName:        toolName,
		Args:            args,
		Guard:           g,
		Evaluator:       requestEvaluator,
		AgentRegistry:   us.AgentRegistry,
		Capabilities:    us.Capabilities,
		EnforcementMode: enforcementMode,
		BackendCaller:   backendCaller,
	}
	ctx, pre, err := guard.RunPipelinePrePhases(ctx, pipelineIn)
	if err != nil {
		if denied, detailedErr := guard.HandlePrePhaseError(err); denied != nil {
			logger.LogWarn("difc", "Access DENIED for agent %s to %s: %s",
				util.HashIdentifierForLog(agentID), denied.Resource.Description, denied.EvalResult.Reason)
			logCoarseDIFCDenial(serverID, toolName, denied)
			if toolSpan.IsRecording() {
				toolSpan.AddEvent("difc.access_denied", oteltrace.WithAttributes(
					attribute.String("reason", denied.EvalResult.Reason),
				))
			}
			tracing.RecordSpanError(toolSpan, detailedErr, "access denied: "+denied.EvalResult.Reason)
			httpStatusCode = 403
			return mcp.NewErrorCallToolResult(detailedErr)
		}
		logger.LogWarn("difc", "Guard labeling failed: %v", err)
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("guard labeling failed: %w", err))
	}
	if toolSpan.IsRecording() {
		toolSpan.AddEvent("difc.pre_phases_complete")
	}
	// Add agent tags snapshot to context for enriched MCP backend logging (Phase 3).
	ctx = context.WithValue(ctx, mcp.AgentTagsSnapshotContextKey, &mcp.AgentTagsSnapshot{
		Secrecy:   difc.TagsToStrings(pre.AgentLabels.GetSecrecyTags()),
		Integrity: difc.TagsToStrings(pre.AgentLabels.GetIntegrityTags()),
	})

	// **Phase 3: Execute the backend call**
	execCtx, execSpan := tracing.StartBackendExecuteSpan(ctx, us.GetTracer(), serverID, toolName)
	defer execSpan.End()

	// Check the circuit breaker before calling the backend.
	cb := us.getCircuitBreaker(serverID)
	if err := cb.Allow(); err != nil {
		tracing.RecordSpanError(execSpan, err, "circuit breaker open")
		httpStatusCode = 429
		return mcp.NewErrorCallToolResult(err)
	}

	backendResult, err := executeBackendToolCall(execCtx, us.launcher, serverID, sessionID, toolName, args)
	if err != nil {
		// Transport errors (connection failure, JSON parse error, etc.) are not rate-limit
		// events and must not affect the consecutive rate-limit counter. Leave the circuit
		// breaker state unchanged so genuine rate-limit history is preserved.
		// Use RecordSpanErrorSafe to avoid leaking internal transport/parse error
		// details to trace backends; the full error is returned to the caller and
		// logged separately.
		tracing.RecordSpanErrorSafe(execSpan, err, "tool execution failed")
		// Explicitly release any in-flight HALF-OPEN probe slot so the breaker
		// doesn't stay wedged until probeStrandedTimeout elapses. This does not
		// touch the consecutive rate-limit counter or state.
		cb.RecordProbeReleased()
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(err)
	}

	// Inspect the tool result for rate-limit indicators from the GitHub MCP server.
	if rateLimited, resetAt := isRateLimitToolResult(backendResult); rateLimited {
		cb.RecordRateLimit(resetAt)
		execSpan.SetAttributes(tracing.RateLimitHit.Bool(true))
		toolSpan.SetAttributes(tracing.RateLimitHit.Bool(true))
		if toolSpan.IsRecording() {
			eventAttrs := []attribute.KeyValue{}
			if !resetAt.IsZero() {
				eventAttrs = append(eventAttrs, attribute.String("reset_at", resetAt.UTC().Format(time.RFC3339)))
			}
			toolSpan.AddEvent("rate_limit.detected", oteltrace.WithAttributes(eventAttrs...))
		}
		tracing.RecordSpanErrorOnAll(errRateLimitExceeded, rateLimitExceededStatus, execSpan, toolSpan)
		httpStatusCode = 429
		// Preserve the original backend error text so the agent sees the actual upstream
		// rate-limit details. ErrCircuitOpen is only returned when cb.Allow() rejects
		// the call before contacting the backend.
		errText := extractRateLimitErrorText(backendResult)
		return &sdk.CallToolResult{
			Content: []sdk.Content{&sdk.TextContent{Text: errText}},
			IsError: true,
		}, backendResult, nil
	}
	cb.RecordSuccess()

	// **Phase 4: Guard labels the response data (for fine-grained filtering)**
	labeledData, err := guard.RunPipelinePhase4(ctx, pipelineIn, pre, backendResult)
	if err != nil {
		logger.LogWarn("difc", "Response labeling failed: %v", err)
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("response labeling failed: %w", err))
	}

	// **Phase 5: Reference Monitor performs fine-grained filtering (if applicable)**
	var finalResult interface{}
	var difcFiltered *difc.FilteredCollectionLabeledData // tracks items removed in filter/propagate mode
	filterResult, err := difc.FilterAndConvertLabeledData(
		requestEvaluator,
		pre.AgentLabels.Secrecy,
		pre.AgentLabels.Integrity,
		pre.Operation,
		labeledData,
		enforcementMode,
	)
	if err != nil {
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("failed to convert labeled data: %w", err))
	}
	if filterResult.Filtered != nil {
		difcFiltered = filterResult.Filtered
		logUnified.Printf("[DIFC] Filtered collection: %d/%d items accessible",
			difcFiltered.GetAccessibleCount(), difcFiltered.TotalCount)

		// **Strict mode: block entire response if ANY item is filtered**
		if filterResult.Blocked {
			logger.LogWarn("difc", "STRICT MODE: Blocking entire response - %d/%d items violate DIFC policy",
				difcFiltered.GetFilteredCount(), difcFiltered.TotalCount)
			blockErr := fmt.Errorf("DIFC policy violation: %d of %d items in response are not accessible to this agent",
				difcFiltered.GetFilteredCount(), difcFiltered.TotalCount)
			httpStatusCode = 403
			return mcp.NewErrorCallToolResult(blockErr)
		}

		if difcFiltered.GetFilteredCount() > 0 {
			logUnified.Printf("[DIFC] Filtered out %d items due to DIFC policy", difcFiltered.GetFilteredCount())
			logFilteredItems(serverID, toolName, difcFiltered)

			// **Single-item entirely filtered**: return a structured MCP error so the agent
			// cannot misinterpret "filtered" as "resource not found" (e.g. issue_read).
			// Only apply this to singular-read tools (get_*, *_read).  Collection tools
			// (list_*, search_*) may legitimately return exactly one item that gets filtered
			// and should still receive the notice-only behavior so agents see an empty list
			// rather than an unexpected error.
			if IsSingularReadTool(toolName) && difcFiltered.GetAccessibleCount() == 0 && difcFiltered.GetFilteredCount() == 1 {
				filteredErr := buildDIFCSingleItemFilteredError(difcFiltered.Filtered[0])
				logger.LogWarn("difc", "Single item filtered — returning MCP error: %v", filteredErr)
				httpStatusCode = 403
				return mcp.NewErrorCallToolResult(filteredErr)
			}
		}
	}

	if labeledData != nil {
		finalResult = filterResult.FinalResult
	} else {
		// No fine-grained labeling - use original backend result
		finalResult = backendResult
	}

	// **Phase 6: Label accumulation (propagate mode)**
	guard.RunPipelinePhase6(pre, labeledData, enforcementMode)

	// Convert finalResult to SDK CallToolResult format
	callResult, err := mcp.ConvertToCallToolResult(finalResult)
	if err != nil {
		httpStatusCode = 500
		return mcp.NewErrorCallToolResult(fmt.Errorf("failed to convert result: %w", err))
	}

	// If items were filtered by DIFC policy in filter/propagate mode, append a notice so
	// the agent knows items exist but were withheld.  Without this, an agent receiving an
	// empty (or partial) list has no way to distinguish "no items" from "items filtered",
	// which can cause targeted-dispatch workflows to silently fall back to scheduled mode.
	if difcFiltered != nil {
		if notice := buildDIFCFilteredNotice(difcFiltered); notice != "" {
			callResult.Content = append(callResult.Content, &sdk.TextContent{Text: notice})
		}
	}

	return callResult, finalResult, nil
}
