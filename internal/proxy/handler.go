package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/githubhttp"
	"github.com/github/gh-aw-mcpg/internal/guard"
	"github.com/github/gh-aw-mcpg/internal/httputil"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/tracing"
	"github.com/github/gh-aw-mcpg/internal/util"
)

var logHandler = logger.ForFile()

// writeDIFCForbidden writes a 403 JSON response for DIFC policy violations.
// Uses the shared WriteErrorResponse helper so that the response shape is consistent
// with all other error responses in the gateway ({"error": ..., "message": ...}).
func writeDIFCForbidden(w http.ResponseWriter, message string) {
	httputil.WriteErrorResponse(w, http.StatusForbidden, "difc_forbidden", message)
}

// rejectProxyRequest standardizes proxy request rejection by logging, recording
// a span error, and writing a JSON error response.
func rejectProxyRequest(w http.ResponseWriter, span oteltrace.Span, status int, code, msg string, err error) {
	if err == nil {
		err = errors.New(msg)
	}
	logger.LogError("proxy", "Request rejected: status=%d code=%s message=%s err=%v", status, code, msg, err)
	if span != nil {
		tracing.RecordSpanError(span, err, msg)
	}
	httputil.WriteErrorResponse(w, status, code, msg)
}

// proxyHandler implements http.Handler and runs the DIFC pipeline on proxied requests.
type proxyHandler struct {
	server *Server
	tracing.CachedTracer
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Avoid logging enclave paths before capability and repository authorization.
	rawPath := r.URL.Path
	if h.server.enclave != nil {
		if normalizedPath, ok := enclavePath(r.URL.Path, r.URL.RawPath); ok {
			rawPath = normalizedPath
		}
	} else {
		// Strip the /api/v3 prefix that GH_HOST adds.
		rawPath = StripGHHostPrefix(r.URL.Path)
	}
	// Preserve query string for upstream forwarding
	fullPath := rawPath
	if r.URL.RawQuery != "" {
		fullPath = rawPath + "?" + r.URL.RawQuery
	}

	if h.server.enclave != nil {
		logHandler.Printf("incoming enclave request: method=%s", r.Method)
	} else if h.server.delegation != nil {
		logHandler.Printf("incoming delegated request: method=%s", r.Method)
	} else {
		logHandler.Printf("incoming %s %s", r.Method, rawPath)
	}

	// Health check endpoint
	if rawPath == "/health" || rawPath == "/healthz" {
		httputil.WriteJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if h.server.enclave != nil {
		h.handleEnclaveRequest(w, r)
		return
	}
	if h.server.delegation != nil {
		h.handleDelegatedRequest(w, r)
		return
	}

	// Reflect endpoint exposes a live DIFC label snapshot.
	if r.Method == http.MethodGet && rawPath == "/reflect" {
		httputil.WriteJSONResponse(w, http.StatusOK, difc.BuildReflectResponse(h.server.DIFCComponents))
		return
	}

	// Safe metadata endpoints carry no user/repo-scoped data and can be passed
	// through without DIFC labeling.
	if r.Method == http.MethodGet && isMetadataPassthroughPath(rawPath) {
		h.passthrough(w, r, fullPath)
		return
	}

	// Only filter read operations (GET + GraphQL POST to /graphql)
	isGraphQL := IsGraphQLPath(rawPath)
	isRead := r.Method == http.MethodGet || (r.Method == http.MethodPost && isGraphQL)
	if !isRead {
		// Pass through write operations unmodified
		h.passthrough(w, r, fullPath)
		return
	}

	// Route the request to a guard tool name
	var toolName string
	var args map[string]interface{}
	var graphQLBody []byte

	if isGraphQL {
		// Read and parse the GraphQL body
		var err error
		graphQLBody, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			rejectProxyRequest(w, oteltrace.SpanFromContext(r.Context()), http.StatusBadRequest, "bad_request", "failed to read request body", err)
			return
		}

		match := MatchGraphQL(graphQLBody)
		if match == nil {
			// Unknown GraphQL query — fail closed: deny rather than risk leaking unfiltered data
			logHandler.Printf("unknown GraphQL query, blocking request: %s", util.Truncate(string(graphQLBody), 500))
			httputil.WriteJSONResponse(w, http.StatusForbidden, map[string]interface{}{
				"errors": []map[string]string{{"message": "access denied: unrecognized GraphQL operation"}},
				"data":   nil,
			})
			return
		}
		// Schema introspection (__type, __schema) is safe metadata — passthrough without DIFC
		if match.ToolName == "graphql_introspection" {
			logHandler.Printf("GraphQL introspection query, passing through")
			clientAuth := r.Header.Get("Authorization")
			resp, respBody := h.forwardAndReadBody(w, r.Context(), oteltrace.SpanFromContext(r.Context()), http.MethodPost, fullPath, bytes.NewReader(graphQLBody), "application/json", clientAuth)
			if resp == nil {
				return
			}
			h.writeResponse(w, resp, respBody)
			return
		}
		toolName = match.ToolName
		args = match.Args

		// Inject guard-required fields (author{login}, authorAssociation) into
		// the GraphQL query so the guard can label items without enrichment.
		graphQLBody = InjectGuardFields(graphQLBody, toolName)
	} else {
		match := MatchRoute(rawPath)
		if match == nil {
			h.handleUnrecognizedPassthrough(w, r, rawPath, fullPath)
			return
		}
		toolName = match.ToolName
		args = match.Args

		// Pass search query parameter so the guard can scope integrity labels
		if q := r.URL.Query().Get("q"); q != "" {
			args["query"] = q
		}
	}

	// Run the DIFC pipeline
	h.handleWithDIFC(w, r, fullPath, toolName, args, graphQLBody)
}

func (h *proxyHandler) handleUnrecognizedPassthrough(w http.ResponseWriter, r *http.Request, rawPath, fullPath string) {
	logger.LogUnrecognizedEndpointPassthrough(r.Method, rawPath)
	logHandler.Printf("unrecognized REST endpoint %s, forwarding with empty labels", rawPath)

	resp, respBody := h.forwardAndReadBody(w, r.Context(), oteltrace.SpanFromContext(r.Context()), r.Method, fullPath, nil, "", r.Header.Get("Authorization"))
	if resp == nil {
		return
	}

	pre := &guard.PipelinePreResult{
		AgentLabels: h.server.AgentRegistry.GetOrCreate(proxyAgentID),
		Resource:    difc.NewLabeledResource(fmt.Sprintf("unrecognized endpoint %s", rawPath)),
		Operation:   difc.OperationRead,
		EvalResult: &difc.EvaluationResult{
			Decision:        difc.AccessAllow,
			SecrecyToAdd:    []difc.Tag{},
			IntegrityToDrop: []difc.Tag{},
		},
	}
	guard.RunPipelinePhase6(pre, nil, h.server.Mode)

	h.writeResponse(w, resp, respBody)
}

// handleWithDIFC runs the 6-phase DIFC pipeline on a request.
func (h *proxyHandler) handleWithDIFC(w http.ResponseWriter, r *http.Request, path, toolName string, args map[string]interface{}, graphQLBody []byte) {
	ctx := r.Context()
	s := h.server
	clientAuth := r.Header.Get("Authorization")
	if s.enclave != nil {
		clientAuth = ""
	}
	backend := &restBackendCaller{server: s, clientAuth: clientAuth}
	evaluator := s.Evaluator
	if assignedRepo := enclaveAssignedRepoFromContext(ctx); assignedRepo != "" {
		evaluator = s.Evaluator.WithSecrecyPropagationMax(difc.Tag("private:" + assignedRepo))
	}

	// Start a DIFC pipeline span covering all phases for this request
	ctx, difcSpan := tracing.StartDIFCPipelineSpan(ctx, h.GetTracer(), toolName, s.logSafePath(r.URL.Path))
	defer difcSpan.End()

	if !s.guardInitialized {
		rejectProxyRequest(w, difcSpan, http.StatusServiceUnavailable, "service_unavailable", "proxy enforcement not configured", nil)
		return
	}

	// **Phases 0–2: Get agent labels, label resource, coarse access check**
	pipelineIn := guard.PipelineInput{
		AgentID:          agentIDFromContext(ctx),
		ToolName:         toolName,
		Args:             args,
		Guard:            s.guard,
		Evaluator:        evaluator,
		AgentRegistry:    s.AgentRegistry,
		Capabilities:     s.Capabilities,
		EnforcementMode:  s.Mode,
		BackendCaller:    backend,
		SensitiveLogging: s.sensitiveLogging(),
	}
	ctx, pre, err := guard.RunPipelinePrePhases(ctx, pipelineIn)
	if err != nil {
		if s.enclave != nil || s.delegation != nil {
			writeEnclaveDenied(w)
			return
		}
		if denied, _ := guard.HandlePrePhaseError(err); denied != nil {
			logHandler.Printf("[DIFC] Phase 2: BLOCKED %s %s — %s", r.Method, path, denied.EvalResult.Reason)
			deniedErr := fmt.Errorf("DIFC policy violation: %s", denied.EvalResult.Reason)
			if difcSpan.IsRecording() {
				difcSpan.AddEvent("difc.access_denied", oteltrace.WithAttributes(
					attribute.String("reason", denied.EvalResult.Reason),
				))
			}
			tracing.RecordSpanError(difcSpan, deniedErr, "access denied: "+denied.EvalResult.Reason)
			writeDIFCForbidden(w, deniedErr.Error())
			return
		}
		rejectProxyRequest(w, difcSpan, http.StatusBadGateway, "bad_gateway", "resource labeling failed", err)
		return
	}
	if difcSpan.IsRecording() {
		difcSpan.AddEvent("difc.pre_phases_complete")
	}

	// **Phase 3: Forward to upstream GitHub API**
	var resp *http.Response
	var respBody []byte

	fwdCtx, fwdSpan := tracing.StartProxyForwardSpan(ctx, h.GetTracer(), toolName, s.logSafePath(r.URL.Path), h.server.upstreamHost())
	defer fwdSpan.End()

	// Artifact ZIP downloads are streamed directly to the client after the authorization
	// check to avoid buffering potentially large binary responses in memory via io.ReadAll.
	if isArtifactDownload(toolName, args) {
		if !h.streamArtifactResponse(w, r, path, fwdCtx, difcSpan, fwdSpan, clientAuth) {
			tracing.RecordSpanError(difcSpan, errors.New("upstream request failed"), "upstream request failed")
			return
		}
		guard.RunPipelinePhase6(pre, nil, s.Mode)
		return
	}

	if graphQLBody != nil {
		resp, respBody = h.forwardAndReadBody(w, fwdCtx, fwdSpan, http.MethodPost, path, bytes.NewReader(graphQLBody), "application/json", clientAuth)
	} else {
		resp, respBody = h.forwardAndReadBody(w, fwdCtx, fwdSpan, r.Method, path, nil, "", clientAuth)
	}
	if resp != nil {
		fwdSpan.SetAttributes(tracing.HTTPResponseStatusCodeKey.Int(resp.StatusCode))
		recordRateLimitSpanEvent(resp, fwdSpan, difcSpan)
	}
	if resp == nil {
		// fwdSpan already received the error via rejectProxyRequest inside forwardAndReadBody;
		// only propagate to the parent difcSpan here to avoid duplicate exception events.
		tracing.RecordSpanError(difcSpan, errors.New("upstream request failed"), "upstream request failed")
		return
	}

	// For non-200 responses, pass through as-is
	if resp.StatusCode >= 300 {
		if s.enclave != nil && resp.StatusCode < 400 {
			writeEnclaveDenied(w)
			return
		}
		h.writeResponse(w, resp, respBody)
		return
	}

	// Parse the response as JSON for DIFC filtering
	var responseData interface{}
	if err := json.Unmarshal(respBody, &responseData); err != nil {
		if s.enclave != nil {
			writeEnclaveDenied(w)
			return
		}
		// Non-JSON response — pass through
		logHandler.Printf("[DIFC] response is not JSON, passing through")
		h.writeResponse(w, resp, respBody)
		return
	}

	// **Phase 4: Guard labels the response**
	labeledData, err := guard.RunPipelinePhase4(ctx, pipelineIn, pre, responseData)
	if err != nil {
		if s.enclave != nil {
			writeEnclaveDenied(w)
			return
		}
		logHandler.Printf("[DIFC] Phase 4 failed: %v", err)
		// On labeling failure, fall back to coarse-grained result
		if pre.EvalResult.IsAllowed() {
			h.writeResponse(w, resp, respBody)
		} else {
			h.writeEmptyResponse(w, resp, responseData)
		}
		return
	}

	// **Phase 5: Fine-grained filtering**
	var finalData interface{}
	var useOriginalBody bool // GraphQL responses need original format preserved
	filterResult, err := difc.FilterAndConvertLabeledData(
		pipelineIn.Evaluator,
		pre.AgentLabels.Secrecy,
		pre.AgentLabels.Integrity,
		pre.Operation,
		labeledData,
		s.Mode,
	)
	if err != nil {
		logHandler.Printf("[DIFC] Phase 5 ToResult failed: %v", err)
		if s.enclave != nil {
			writeEnclaveDenied(w)
			return
		}
		h.writeEmptyResponse(w, resp, responseData)
		return
	}

	if labeledData != nil {
		if filtered := filterResult.Filtered; filtered != nil {

			logHandler.Printf("[DIFC] Phase 5: %d/%d items accessible",
				filtered.GetAccessibleCount(), filtered.TotalCount)

			// Log filtered items
			if filtered.GetFilteredCount() > 0 {
				logHandler.Printf("[DIFC] Filtered %d items", filtered.GetFilteredCount())
				logger.LogInfo("proxy", "DIFC filtered %d/%d items for %s %s (tool=%s)",
					filtered.GetFilteredCount(), filtered.TotalCount, r.Method, s.logSafePath(path), toolName)
			}

			// Strict mode: block entire response if any item filtered
			if filterResult.Blocked {
				logHandler.Printf("[DIFC] STRICT: blocking response — %d filtered items", filtered.GetFilteredCount())
				writeDIFCForbidden(w, fmt.Sprintf("DIFC policy violation: %d of %d items not accessible",
					filtered.GetFilteredCount(), filtered.TotalCount))
				return
			}

			// For GraphQL: if nothing was filtered, return original response body
			// to preserve the exact response format (ToResult transforms the structure)
			if graphQLBody != nil && filtered.GetFilteredCount() == 0 {
				useOriginalBody = true
			} else if graphQLBody != nil {
				// GraphQL with filtered items: reconstruct the response with only accessible items
				logHandler.Printf("[DIFC] GraphQL response: %d/%d items filtered, reconstructing response",
					filtered.GetFilteredCount(), filtered.TotalCount)
				finalData = rebuildGraphQLResponse(responseData, filtered)
			} else {
				finalData = filterResult.FinalResult
				// Re-wrap search responses to preserve the envelope
				finalData = rewrapSearchResponse(responseData, finalData)
				// Unwrap single-object responses (e.g., get_file_contents)
				finalData = unwrapSingleObject(responseData, finalData)
			}
		} else {
			// Simple labeled data — already passed coarse check
			if graphQLBody != nil {
				useOriginalBody = true
			} else {
				finalData = filterResult.FinalResult
			}
		}
	} else {
		// No fine-grained labels — use coarse result
		if pre.EvalResult.IsAllowed() {
			finalData = responseData
		} else {
			h.writeEmptyResponse(w, resp, responseData)
			return
		}
	}

	// **Phase 6: Label accumulation (propagate mode)**
	guard.RunPipelinePhase6(pre, labeledData, s.Mode)

	// Write the filtered response
	if useOriginalBody {
		// GraphQL: return original upstream response to preserve exact format
		logHandler.Printf("[DIFC] returning original response body (GraphQL, no items filtered)")
		h.writeResponse(w, resp, respBody)
	} else {
		filteredJSON, err := json.Marshal(finalData)
		if err != nil {
			rejectProxyRequest(w, difcSpan, http.StatusInternalServerError, "internal_error", "failed to serialize filtered response", err)
			return
		}
		copyResponseHeaders(w, resp)
		httputil.WriteJSONResponse(w, resp.StatusCode, json.RawMessage(filteredJSON))
	}
}

// passthrough forwards a request to the upstream GitHub API without DIFC filtering.
func (h *proxyHandler) passthrough(w http.ResponseWriter, r *http.Request, path string) {
	logHandler.Printf("passthrough %s %s", r.Method, h.server.logSafePath(path))

	var body io.Reader
	if r.Body != nil {
		body = r.Body
		defer r.Body.Close()
	}

	resp, respBody := h.forwardAndReadBody(w, r.Context(), oteltrace.SpanFromContext(r.Context()), r.Method, path, body, r.Header.Get("Content-Type"), r.Header.Get("Authorization"))
	if resp == nil {
		return
	}

	h.writeResponse(w, resp, respBody)
}

// writeResponse writes an upstream response to the client.
// When the upstream signals rate-limiting (HTTP 429 or X-RateLimit-Remaining == 0),
// it injects a Retry-After header and logs the event at ERROR level.
func (h *proxyHandler) writeResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	copyResponseHeaders(w, resp)
	injectRetryAfterIfRateLimited(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// writeEmptyResponse writes an empty JSON response matching the shape of the original data.
// originalData should be the parsed upstream response; nil or unrecognized types fall back to "[]".
// For JSON arrays it writes "[]", for GraphQL objects with a "data" key it writes {"data":null},
// and for other JSON objects it writes "{}".
func (h *proxyHandler) writeEmptyResponse(w http.ResponseWriter, resp *http.Response, originalData interface{}) {
	copyResponseHeaders(w, resp)

	var empty string
	switch obj := originalData.(type) {
	case []interface{}:
		empty = "[]"
	case map[string]interface{}:
		// GraphQL responses wrap their payload in a "data" key
		if _, ok := obj["data"]; ok {
			empty = `{"data":null}`
		} else {
			empty = "{}"
		}
	default:
		empty = "[]" // safe default for nil or unknown types
	}
	logHandler.Printf("writeEmptyResponse: shape=%s, status=%d", empty, resp.StatusCode)
	httputil.WriteJSONResponse(w, resp.StatusCode, json.RawMessage(empty))
}

// forwardAndReadBody forwards a request to the upstream GitHub API and reads the
// entire response body. On success it returns the response and body bytes. It writes
// a 502 error to w and returns nil, nil on failure.
// span is the active tracing span for error recording; pass nil if no span is available.
func (h *proxyHandler) forwardAndReadBody(
	w http.ResponseWriter, ctx context.Context, span oteltrace.Span,
	method, path string, body io.Reader, contentType, clientAuth string,
) (*http.Response, []byte) {
	// Enclave and delegation modes admit only private, dynamically-discovered
	// repository paths; never write the raw path to logs or error messages in
	// those modes, only its non-reversible hash.
	pathForLog := h.server.logSafePath(path)
	logHandler.Printf("forwardAndReadBody: %s %s", method, pathForLog)
	resp, err := h.server.forwardToGitHub(ctx, method, path, body, contentType, clientAuth)
	if err != nil {
		rejectProxyRequest(w, span, http.StatusBadGateway, "bad_gateway", "upstream request failed", fmt.Errorf("%s %s: %w", method, pathForLog, err))
		return nil, nil
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		rejectProxyRequest(w, span, http.StatusBadGateway, "bad_gateway", "failed to read upstream response", fmt.Errorf("%s %s status=%d: %w", method, pathForLog, resp.StatusCode, err))
		return nil, nil
	}
	logHandler.Printf("forwardAndReadBody: %s %s -> status=%d bodyLen=%d", method, pathForLog, resp.StatusCode, len(respBody))
	return resp, respBody
}

// isArtifactDownload reports whether the tool call is for an artifact ZIP download
// (actions_get with method=download_workflow_run_artifact). These responses are binary
// and potentially very large; they are streamed rather than buffered via io.ReadAll.
func isArtifactDownload(toolName string, args map[string]interface{}) bool {
	if toolName != "actions_get" {
		return false
	}
	method, _ := args["method"].(string)
	return method == "download_workflow_run_artifact"
}

// streamArtifactResponse forwards an artifact ZIP download to the client using
// io.Copy to stream the body without buffering it fully in memory. This is safe
// because artifact responses are binary (no DIFC JSON filtering applies) and can
// be arbitrarily large. Redirects (3xx) and error responses have empty or small
// bodies and are forwarded the same way.
// Returns true on success; on upstream failure it writes a 502 to w and returns false.
func (h *proxyHandler) streamArtifactResponse(
	w http.ResponseWriter, r *http.Request, path string,
	ctx context.Context, difcSpan, fwdSpan oteltrace.Span, clientAuth string,
) bool {
	resp, err := h.server.forwardToGitHub(ctx, r.Method, path, nil, "", clientAuth)
	if err != nil {
		rejectProxyRequest(w, fwdSpan, http.StatusBadGateway, "bad_gateway", "upstream request failed",
			fmt.Errorf("%s %s: %w", r.Method, h.server.logSafePath(path), err))
		return false
	}
	defer resp.Body.Close()

	fwdSpan.SetAttributes(tracing.HTTPResponseStatusCodeKey.Int(resp.StatusCode))
	recordRateLimitSpanEvent(resp, fwdSpan, difcSpan)

	copyResponseHeaders(w, resp)
	injectRetryAfterIfRateLimited(w, resp)
	w.WriteHeader(resp.StatusCode)
	if _, copyErr := io.Copy(w, resp.Body); copyErr != nil {
		// Headers and status are already sent; log and continue.
		logHandler.Printf("streamArtifactResponse: body copy error: %v", copyErr)
	}
	return true
}

// copyResponseHeaders copies relevant headers from upstream to the client response.
func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for _, h := range []string{
		"Content-Type",
		"Content-Disposition",
		"Location",
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
		"X-RateLimit-Resource", "X-RateLimit-Used",
		"Link", // pagination
		"X-GitHub-Request-Id",
	} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// injectRetryAfterIfRateLimited inspects the upstream response for rate-limit signals
// (HTTP 429 or X-Ratelimit-Remaining == 0). When detected it:
//  1. Injects a Retry-After header so the client knows when to retry.
//  2. Logs the event at ERROR level so operators can monitor rate-limit incidents.
func injectRetryAfterIfRateLimited(w http.ResponseWriter, resp *http.Response) {
	isRateLimited, resetHeader, remaining := githubhttp.RateLimitSignal(resp)
	if !isRateLimited {
		return
	}

	resetAt := githubhttp.ParseRateLimitResetHeader(resetHeader)
	retryAfter := githubhttp.ComputeRetryAfter(resetAt)

	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

	logger.LogError("client",
		"upstream rate limit hit: status=%d X-Ratelimit-Remaining=%s X-Ratelimit-Reset=%s retry-after=%ds",
		resp.StatusCode, remaining, resetHeader, retryAfter)
}

// recordRateLimitSpanEvent marks the forward span and records a DIFC span event
// when the upstream response indicates GitHub API rate limiting.
func recordRateLimitSpanEvent(resp *http.Response, fwdSpan, difcSpan oteltrace.Span) {
	if rateLimited, resetHeader, _ := githubhttp.RateLimitSignal(resp); rateLimited {
		fwdSpan.SetAttributes(tracing.RateLimitHit.Bool(true))
		if difcSpan.IsRecording() {
			eventAttrs := []attribute.KeyValue{}
			if resetAt := githubhttp.ParseRateLimitResetHeader(resetHeader); !resetAt.IsZero() {
				eventAttrs = append(eventAttrs, attribute.String("reset_at", resetAt.UTC().Format(time.RFC3339)))
			}
			difcSpan.AddEvent("rate_limit.detected", oteltrace.WithAttributes(eventAttrs...))
		}
	}
}

var metadataPassthrough = map[string]bool{
	"/meta":       true,
	"/rate_limit": true,
	"/octocat":    true,
	"/zen":        true,
	"/versions":   true,
}

func isMetadataPassthroughPath(path string) bool {
	return metadataPassthrough[path]
}
