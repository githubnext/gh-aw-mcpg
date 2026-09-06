package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/github/gh-aw-mcpg/internal/delegation"
	"github.com/github/gh-aw-mcpg/internal/enclavegithub"
	"github.com/github/gh-aw-mcpg/internal/httputil"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/tracing"
	"github.com/github/gh-aw-mcpg/internal/util"
)

var logDelegation = logger.ForFile()

const delegationControlPath = "/internal/awf-enclave-mcp-control/"

type delegationState struct {
	store      *delegation.Store
	capability *delegation.ControlCapability
	statePath  string
}

// DelegationConfig enables runtime repository-read delegation and its
// AWF-authenticated private control channel.
type DelegationConfig struct {
	Store             *delegation.Store
	Capability        *delegation.ControlCapability
	StatePath         string
	ControlListenAddr string
}

func newDelegationState(cfg *DelegationConfig) (*delegationState, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Store == nil || cfg.Capability == nil || cfg.StatePath == "" {
		return nil, fmt.Errorf("delegation store, control capability, and state path are required")
	}
	return &delegationState{store: cfg.Store, capability: cfg.Capability, statePath: cfg.StatePath}, nil
}

func (h *proxyHandler) handleDelegationControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || h.server.delegation.capability.Authenticate(r.Header.Get("Authorization")) != nil {
		logDelegation.Printf("Delegation control access denied: method=%s path=%s", r.Method, r.URL.Path)
		httputil.WriteErrorResponse(w, http.StatusForbidden, "delegation_access_denied", "delegation control access denied")
		return
	}
	logDelegation.Printf("Handling delegation control request: path=%s", r.URL.Path)

	switch r.URL.Path {
	case delegationControlPath + "create-or-confirm":
		var request delegation.CreateOrConfirmRequest
		if !decodeDelegationJSON(w, r, &request) {
			return
		}
		result, err := h.server.delegation.store.CreateOrConfirm(request)
		if err != nil {
			if !h.persistDelegationState(w) {
				return
			}
			httputil.WriteErrorResponse(w, http.StatusForbidden, "delegation_request_denied", "delegation request denied")
			return
		}

		if !h.persistDelegationState(w) {
			return
		}
		httputil.WriteJSONResponse(w, http.StatusOK, result)
	case delegationControlPath + "revoke":
		var request struct {
			Handle string `json:"handle"`
		}
		if !decodeDelegationJSON(w, r, &request) {
			return
		}
		if err := h.server.delegation.store.Revoke(request.Handle); err != nil {
			logDelegation.Printf("Delegation revoke failed for handle_hash=%s", util.HashForLog(request.Handle, 16, ""))
			httputil.WriteErrorResponse(w, http.StatusInternalServerError, "delegation_revoke_failed", "delegation revoke failed")
			return
		}
		if !h.persistDelegationState(w) {
			return
		}
		httputil.WriteJSONResponse(w, http.StatusOK, map[string]bool{"revoked": true})
	case delegationControlPath + "revoke-by-labels":
		var request struct {
			RunID          string `json:"run_id"`
			EnclaveEntryID string `json:"enclave_entry_id"`
		}
		if !decodeDelegationJSON(w, r, &request) {
			return
		}
		revoked := h.server.delegation.store.RevokeByLabels(request.RunID, request.EnclaveEntryID)
		logDelegation.Printf("Revoked %d delegation(s) by labels: run_hash=%s enclave_entry_id_hash=%s", revoked, util.HashForLog(request.RunID, 16, ""), util.HashForLog(request.EnclaveEntryID, 16, ""))
		if !h.persistDelegationState(w) {
			return
		}
		httputil.WriteJSONResponse(w, http.StatusOK, map[string]int{"revoked": revoked})
	case delegationControlPath + "status":
		var request struct {
			RunID          string `json:"run_id"`
			EnclaveEntryID string `json:"enclave_entry_id"`
		}
		if !decodeDelegationJSON(w, r, &request) {
			return
		}
		if request.RunID == "" || request.EnclaveEntryID == "" {
			httputil.WriteErrorResponse(w, http.StatusBadRequest, "delegation_status_invalid_request", "run_id and enclave_entry_id are required")
			return
		}
		status := h.server.delegation.store.Status()
		httputil.WriteJSONResponse(w, http.StatusOK, map[string]any{
			"recovery_incomplete": status.RecoveryIncomplete,
			"generation":          status.Generation,
			"live_identity_count": status.LiveIdentityCount,
			"labelled_handles":    h.server.delegation.store.LabelHandles(request.RunID, request.EnclaveEntryID),
		})
	case delegationControlPath + "reconcile":
		// Reconcile explicitly clears the recovery-incomplete flag once
		// AWF has inspected (and, via revoke/revoke-by-labels, revoked)
		// any outstanding labelled state from a prior restart, letting new
		// dynamic admissions resume.
		h.server.delegation.store.MarkReconciled()
		if !h.persistDelegationState(w) {
			return
		}
		httputil.WriteJSONResponse(w, http.StatusOK, map[string]bool{"reconciled": true})
	default:
		http.NotFound(w, r)
	}
}

// ControlHandler returns the private control-plane handler. It is intentionally
// separate from Handler so executor-facing GitHub traffic cannot reach control
// operations even if it presents a valid executor bearer.
func (s *Server) ControlHandler() http.Handler {
	handler := &proxyHandler{
		server:       s,
		CachedTracer: tracing.CachedTracer{Tracer: tracing.Tracer()},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.delegation == nil || !strings.HasPrefix(r.URL.Path, delegationControlPath) {
			http.NotFound(w, r)
			return
		}
		handler.handleDelegationControl(w, r)
	})
}

func (h *proxyHandler) persistDelegationState(w http.ResponseWriter) bool {
	if err := h.server.delegation.store.SaveState(h.server.delegation.statePath); err != nil {
		httputil.WriteErrorResponse(w, http.StatusInternalServerError, "delegation_state_persist_failed", "delegation state persistence failed")
		return false
	}
	return true
}

func decodeDelegationJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		httputil.WriteErrorResponse(w, http.StatusBadRequest, "invalid_delegation_request", "invalid delegation request")
		return false
	}
	return true
}

func (h *proxyHandler) handleDelegatedRequest(w http.ResponseWriter, r *http.Request) {
	path, ok := enclavePath(r.URL.Path, r.URL.RawPath)
	if !ok || r.Method != http.MethodGet || hasEnclaveGETBody(r) {
		writeEnclaveDenied(w)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeEnclaveDenied(w)
		return
	}
	route, err := enclavegithub.MatchRoute(path, query)
	if err != nil {
		logDelegation.Printf("No matching enclave route for path_hash=%s", util.HashForLog(path, 16, ""))
		writeEnclaveDenied(w)
		return
	}
	toolName, args := enclaveToolAndArgs(route)
	if toolName == "" {
		writeEnclaveDenied(w)
		return
	}
	handle, err := h.server.delegation.store.AuthorizeExecutor(r.Header.Get("Authorization"), route.FullRepo(), toolName)
	if err != nil {
		logDelegation.Printf("Executor not authorized for tool=%s repo_hash=%s", toolName, util.HashForLog(route.FullRepo(), 16, ""))
		writeEnclaveDenied(w)
		return
	}
	fullPath := path
	if r.URL.RawQuery != "" {
		fullPath += "?" + r.URL.RawQuery
	}
	logDelegation.Printf("Delegating request: tool=%s repo_hash=%s path_hash=%s", toolName, util.HashForLog(route.FullRepo(), 16, ""), util.HashForLog(path, 16, ""))
	// Bind this request to a delegation-specific isolation context, keyed
	// on the identity's own opaque handle and assigned repository, rather
	// than letting it fall through to the shared fallback proxy DIFC
	// identity used by ordinary (non-delegated, non-enclave) requests.
	ctx := withEnclaveAuthorization(r.Context(), "delegation:"+handle, route.FullRepo())
	h.handleWithDIFC(w, r.WithContext(ctx), fullPath, toolName, args, nil)
}
