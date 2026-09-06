package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/github/gh-aw-mcpg/internal/delegation"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/sanitize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Values chosen so a substring match cannot succeed by accident: none of them
// appear in any other literal in this package.
const (
	redactionOwner    = "octosecretorg"
	redactionRepo     = "privaterepo9"
	redactionSelector = redactionOwner + "/" + redactionRepo
	redactionRunID    = "run-8f3c1d92"
	redactionEntryID  = "entry-5b7a"
	redactionInvID    = "inv-2e6d"
)

// captureProxyLogs runs f with DEBUG=* and returns everything the proxy
// package's debug loggers wrote to stderr.
//
// Package-level loggers resolve DEBUG once, at package initialization, so they
// have to be rebuilt after the environment is set or they stay disabled and
// the test would trivially "pass" on empty output.
func captureProxyLogs(t *testing.T, f func()) string {
	t.Helper()
	t.Setenv("DEBUG", "*")
	t.Setenv("DEBUG_COLORS", "0")

	prevHandler, prevProxy, prevDelegation := logHandler, logProxy, logDelegation
	logHandler = logger.New("proxy:handler")
	logProxy = logger.New("proxy:proxy")
	logDelegation = logger.New("proxy:delegation")
	require.True(t, logHandler.Enabled(), "the capture harness must actually enable debug logging")
	t.Cleanup(func() {
		logHandler, logProxy, logDelegation = prevHandler, prevProxy, prevDelegation
	})

	original := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	var (
		wg  sync.WaitGroup
		buf bytes.Buffer
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()

	func() {
		defer func() {
			os.Stderr = original
			_ = w.Close()
		}()
		f()
	}()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

// assertNoDelegatedSecrets asserts that no part of a delegated invocation's
// secret material survived into logs. The selector is the private repository
// AWF admitted at runtime; the run, entry, and invocation identifiers scope it
// and would let an observer correlate a redacted selector back to its source.
func assertNoDelegatedSecrets(t *testing.T, logs string, extra ...string) {
	t.Helper()
	assert := assert.New(t)

	assert.NotContains(logs, redactionSelector, "the raw private repository selector must never be logged")
	assert.NotContains(logs, redactionOwner, "the raw owner must never be logged")
	assert.NotContains(logs, redactionRepo, "the raw repository name must never be logged")
	assert.NotContains(logs, redactionRunID, "the raw run ID must never be logged")
	assert.NotContains(logs, redactionEntryID, "the raw enclave entry ID must never be logged")
	assert.NotContains(logs, redactionInvID, "the raw invocation ID must never be logged")
	for _, value := range extra {
		require.NotEmpty(t, value, "the value under test must be non-empty or the assertion is vacuous")
		assert.NotContainsf(logs, value, "%q must never be logged", value)
	}
}

// newDelegationRedactionServer builds a delegation-mode proxy pointed at
// upstreamURL, admits one delegated identity through the control plane, and
// returns the server plus the executor bearer the data plane must present.
func newDelegationRedactionServer(t *testing.T, upstreamURL string) (*Server, string) {
	t.Helper()

	envelope := &delegation.Envelope{
		RunID:               redactionRunID,
		EnclaveBackend:      "awf-enclave",
		AllowedRepositories: []string{redactionSelector},
		ToolPolicy:          delegation.ToolPolicyGitHubRepositoryReadV1,
		AllowedSchemaHashes: []string{"sha256:test"},
		MaxIdentityTTL:      time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	store, err := delegation.NewStore(envelope, 1)
	require.NoError(t, err)
	capabilityKey := strings.Repeat("c", 32)
	capability, err := delegation.NewControlCapability(capabilityKey)
	require.NoError(t, err)

	s, err := New(context.Background(), Config{
		WasmPath:     writeSuccessGuardWasm(t),
		Policy:       markerFreePolicyJSON,
		GitHubToken:  "gh-token-secret",
		GitHubAPIURL: upstreamURL,
		Delegation: &DelegationConfig{
			Store:      store,
			Capability: capability,
			StatePath:  t.TempDir() + "/state.json",
		},
	})
	require.NoError(t, err)
	closeGuard(t, s)
	require.True(t, s.sensitiveLogging(), "delegation mode must mark logging sensitive")
	require.True(t, sanitize.PrivateSelectorRedactionEnabled(),
		"delegation mode must enable process-wide private-selector redaction")

	t.Cleanup(func() { sanitize.SetPrivateSelectorRedaction(false) })

	identity, err := store.CreateOrConfirm(delegation.CreateOrConfirmRequest{
		RunID:          redactionRunID,
		EnclaveBackend: "awf-enclave",
		EnclaveEntryID: redactionEntryID,
		InvocationID:   redactionInvID,
		Repository:     redactionSelector,
		ToolPolicy:     delegation.ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:     "sha256:test",
		RequestedTTL:   time.Minute,
		IdempotencyKey: "idem-1",
	})
	require.NoError(t, err)
	return s, identity.ExecutorBearer
}

func delegatedIssueRequest(bearer string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/repos/"+redactionSelector+"/issues/7", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	return req
}

// TestDelegatedRequestLoggingRedactsPrivateSelectors drives a delegated
// request all the way through route matching, executor authorization, the DIFC
// pipeline, and upstream forwarding with DEBUG=* and asserts that not one of
// those stages disclosed the private repository selector or the identifiers
// that scope it.
func TestDelegatedRequestLoggingRedactsPrivateSelectors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"number":7,"title":"internal","state":"open"}`))
	}))
	defer upstream.Close()

	s, bearer := newDelegationRedactionServer(t, upstream.URL)
	handler := s.Handler()
	directHandler := &proxyHandler{server: s}

	rec := httptest.NewRecorder()
	logs := captureProxyLogs(t, func() {
		handler.ServeHTTP(rec, delegatedIssueRequest(bearer))

		// Drive the upstream forward and the guard enrichment caller
		// directly as well. Whether the DIFC pipeline admits this request
		// depends on the guard policy under test, and these two sites
		// received the raw path before this change, so they must be
		// exercised unconditionally rather than only on the happy path.
		forwardRec := httptest.NewRecorder()
		resp, body := directHandler.forwardAndReadBody(
			forwardRec, context.Background(), oteltrace.SpanFromContext(context.Background()),
			http.MethodGet, "/repos/"+redactionSelector+"/issues/7", nil, "", "")
		require.NotNil(t, resp)
		require.NotEmpty(t, body)

		caller := &restBackendCaller{server: s}
		_, _ = caller.CallTool(context.Background(), "get_issue", map[string]any{
			"owner": redactionOwner, "repo": redactionRepo, "issue_number": float64(7),
		})
	})

	require.NotEmpty(t, logs, "the delegated request must produce debug output to assert against")
	assert.Contains(t, logs, "forwardAndReadBody", "the forwarding stage must still be diagnosable")
	assert.Contains(t, logs, "restBackendCaller", "guard enrichment must still be diagnosable")
	assertNoDelegatedSecrets(t, logs, bearer)
}

// TestDelegatedRequestLoggingRedactsOnUpstreamFailure covers the error path.
// Upstream failures wrap the request path into an error string that
// rejectProxyRequest hands to logger.LogError, which is not gated on DEBUG, so
// it is the easiest way for a selector to escape.
func TestDelegatedRequestLoggingRedactsOnUpstreamFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := upstream.URL
	upstream.Close() // force a connection failure on every forward

	s, bearer := newDelegationRedactionServer(t, upstreamURL)
	handler := s.Handler()

	rec := httptest.NewRecorder()
	logs := captureProxyLogs(t, func() {
		handler.ServeHTTP(rec, delegatedIssueRequest(bearer))
	})

	require.NotEmpty(t, logs)
	assertNoDelegatedSecrets(t, logs, bearer)
}

// TestDelegatedRequestLoggingRedactsWhenExecutorUnauthorized covers the
// rejection path taken by a stale or forged bearer, which logs before any
// identity is resolved.
func TestDelegatedRequestLoggingRedactsWhenExecutorUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	s, _ := newDelegationRedactionServer(t, upstream.URL)
	handler := s.Handler()

	rec := httptest.NewRecorder()
	logs := captureProxyLogs(t, func() {
		handler.ServeHTTP(rec, delegatedIssueRequest("dlgbearer_not_a_real_bearer"))
	})

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assertNoDelegatedSecrets(t, logs)
}

// TestDelegationControlLoggingRedactsPrivateSelectors covers the control
// plane: create-or-confirm, status, and revoke all receive the raw selector
// and the run/entry/invocation identifiers in their request bodies.
func TestDelegationControlLoggingRedactsPrivateSelectors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	s, bearer := newDelegationRedactionServer(t, upstream.URL)
	handler := &proxyHandler{server: s}
	capabilityKey := strings.Repeat("c", 32)

	post := func(op string, payload any) *httptest.ResponseRecorder {
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, delegationControlPath+op, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+capabilityKey)
		rec := httptest.NewRecorder()
		handler.handleDelegationControl(rec, req)
		return rec
	}

	logs := captureProxyLogs(t, func() {
		require.Equal(t, http.StatusOK, post("create-or-confirm", delegation.CreateOrConfirmRequest{
			RunID:          redactionRunID,
			EnclaveBackend: "awf-enclave",
			EnclaveEntryID: redactionEntryID,
			InvocationID:   redactionInvID,
			Repository:     redactionSelector,
			ToolPolicy:     delegation.ToolPolicyGitHubRepositoryReadV1,
			SchemaHash:     "sha256:test",
			RequestedTTL:   time.Minute,
			IdempotencyKey: "idem-1",
		}).Code)

		require.Equal(t, http.StatusOK, post("status", map[string]string{
			"run_id":           redactionRunID,
			"enclave_entry_id": redactionEntryID,
		}).Code)

		require.Equal(t, http.StatusOK, post("revoke-by-labels", map[string]string{
			"run_id":           redactionRunID,
			"enclave_entry_id": redactionEntryID,
		}).Code)
	})

	assertNoDelegatedSecrets(t, logs, bearer, capabilityKey)
}
