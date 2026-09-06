package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/github/gh-aw-mcpg/internal/delegation"
	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDelegationControlCreateRequiresCapability(t *testing.T) {
	envelope := &delegation.Envelope{
		RunID:               "run",
		EnclaveBackend:      "backend",
		AllowedRepositories: []string{"github/gh-aw"},
		ToolPolicy:          delegation.ToolPolicyGitHubRepositoryReadV1,
		AllowedSchemaHashes: []string{"sha256:test"},
		MaxIdentityTTL:      time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	store, err := delegation.NewStore(envelope, 1)
	require.NoError(t, err)
	capabilityKey := strings.Repeat("a", 32)
	capability, err := delegation.NewControlCapability(capabilityKey)
	require.NoError(t, err)
	handler := &proxyHandler{server: &Server{delegation: &delegationState{store: store, capability: capability, statePath: t.TempDir() + "/state.json"}}}

	body, err := json.Marshal(delegation.CreateOrConfirmRequest{
		RunID: "run", EnclaveBackend: "backend", EnclaveEntryID: "entry", InvocationID: "inv",
		Repository: "github/gh-aw", ToolPolicy: delegation.ToolPolicyGitHubRepositoryReadV1,
		SchemaHash: "sha256:test", RequestedTTL: time.Minute, IdempotencyKey: "key",
	})
	require.NoError(t, err)

	denied := httptest.NewRecorder()
	handler.handleDelegationControl(denied, httptest.NewRequest(http.MethodPost, delegationControlPath+"create-or-confirm", bytes.NewReader(body)))
	assert.Equal(t, http.StatusForbidden, denied.Code)

	allowed := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, delegationControlPath+"create-or-confirm", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+capabilityKey)
	handler.handleDelegationControl(allowed, request)
	assert.Equal(t, http.StatusOK, allowed.Code)
}

func TestDelegationControlStatusAndReconcile(t *testing.T) {
	envelope := &delegation.Envelope{
		RunID:               "run",
		EnclaveBackend:      "backend",
		AllowedRepositories: []string{"github/gh-aw"},
		ToolPolicy:          delegation.ToolPolicyGitHubRepositoryReadV1,
		AllowedSchemaHashes: []string{"sha256:test"},
		MaxIdentityTTL:      time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	store, err := delegation.NewStore(envelope, 1)
	require.NoError(t, err)
	capabilityKey := strings.Repeat("a", 32)
	capability, err := delegation.NewControlCapability(capabilityKey)
	require.NoError(t, err)
	handler := &proxyHandler{server: &Server{delegation: &delegationState{store: store, capability: capability, statePath: t.TempDir() + "/state.json"}}}

	createBody, err := json.Marshal(delegation.CreateOrConfirmRequest{
		RunID: "run", EnclaveBackend: "backend", EnclaveEntryID: "entry", InvocationID: "inv",
		Repository: "github/gh-aw", ToolPolicy: delegation.ToolPolicyGitHubRepositoryReadV1,
		SchemaHash: "sha256:test", RequestedTTL: time.Minute, IdempotencyKey: "key",
	})
	require.NoError(t, err)
	createReq := httptest.NewRequest(http.MethodPost, delegationControlPath+"create-or-confirm", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+capabilityKey)
	createRec := httptest.NewRecorder()
	handler.handleDelegationControl(createRec, createReq)
	require.Equal(t, http.StatusOK, createRec.Code)

	statusBody, err := json.Marshal(map[string]string{"run_id": "run", "enclave_entry_id": "entry"})
	require.NoError(t, err)
	statusReq := httptest.NewRequest(http.MethodPost, delegationControlPath+"status", bytes.NewReader(statusBody))
	statusReq.Header.Set("Authorization", "Bearer "+capabilityKey)
	statusRec := httptest.NewRecorder()
	handler.handleDelegationControl(statusRec, statusReq)
	require.Equal(t, http.StatusOK, statusRec.Code)

	var status struct {
		RecoveryIncomplete bool     `json:"recovery_incomplete"`
		Generation         uint64   `json:"generation"`
		LiveIdentityCount  int      `json:"live_identity_count"`
		LabelledHandles    []string `json:"labelled_handles"`
	}
	require.NoError(t, json.Unmarshal(statusRec.Body.Bytes(), &status))
	assert.False(t, status.RecoveryIncomplete)
	assert.Equal(t, uint64(1), status.Generation)
	assert.Equal(t, 1, status.LiveIdentityCount)
	assert.Len(t, status.LabelledHandles, 1)

	reconcileReq := httptest.NewRequest(http.MethodPost, delegationControlPath+"reconcile", bytes.NewReader([]byte("{}")))
	reconcileReq.Header.Set("Authorization", "Bearer "+capabilityKey)
	reconcileRec := httptest.NewRecorder()
	handler.handleDelegationControl(reconcileRec, reconcileReq)
	assert.Equal(t, http.StatusOK, reconcileRec.Code)
	assert.JSONEq(t, `{"reconciled":true}`, reconcileRec.Body.String())

	missingFieldsReq := httptest.NewRequest(http.MethodPost, delegationControlPath+"status", bytes.NewReader([]byte(`{"run_id":"run"}`)))
	missingFieldsReq.Header.Set("Authorization", "Bearer "+capabilityKey)
	missingFieldsRec := httptest.NewRecorder()
	handler.handleDelegationControl(missingFieldsRec, missingFieldsReq)
	assert.Equal(t, http.StatusBadRequest, missingFieldsRec.Code, "status must require both run_id and enclave_entry_id")
}

func TestNew_DelegationMode_InheritsGuardIntegrityLabelsAndPropagateMode(t *testing.T) {
	wasmPath := writeSuccessGuardWasm(t)

	envelope := &delegation.Envelope{
		RunID:               "run",
		EnclaveBackend:      "backend",
		AllowedRepositories: []string{"github/gh-aw"},
		ToolPolicy:          delegation.ToolPolicyGitHubRepositoryReadV1,
		AllowedSchemaHashes: []string{"sha256:test"},
		MaxIdentityTTL:      time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
	}
	store, err := delegation.NewStore(envelope, 1)
	require.NoError(t, err)
	capabilityKey := strings.Repeat("a", 32)
	capability, err := delegation.NewControlCapability(capabilityKey)
	require.NoError(t, err)

	s, err := New(context.Background(), Config{
		WasmPath:    wasmPath,
		Policy:      markerFreePolicyJSON,
		GitHubToken: "gh-token-secret",
		Delegation: &DelegationConfig{
			Store:      store,
			Capability: capability,
			StatePath:  t.TempDir() + "/state.json",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, s)
	closeGuard(t, s)

	// Mode must be explicitly set to propagate
	assert.Equal(t, difc.EnforcementPropagate, s.Mode)

	// Initial proxyAgentID labels should have been populated by guard
	proxyLabels, ok := s.AgentRegistry.Get("proxy")
	require.True(t, ok)
	proxyIntegrity := proxyLabels.GetIntegrityTags()
	require.NotEmpty(t, proxyIntegrity, "proxyAgentID must have guard-assigned integrity tags")

	// Newly created delegation agent must inherit those default integrity tags
	delegatedAgent := s.AgentRegistry.GetOrCreate("delegation:handle_12345")
	assert.Equal(t, proxyIntegrity, delegatedAgent.GetIntegrityTags(), "delegated agent must inherit guard-derived integrity tags")
}
