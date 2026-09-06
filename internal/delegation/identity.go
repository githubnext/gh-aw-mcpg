package delegation

import "time"

// CreateOrConfirmRequest is an AWF-authenticated request to create or
// confirm exactly one delegated identity. Every field must be a strict
// subset of the compiler-installed Envelope; the Store rejects anything
// wider than the envelope allows.
type CreateOrConfirmRequest struct {
	// RunID must equal the envelope's bound workflow run.
	RunID string `json:"run_id"`
	// EnclaveBackend must equal the envelope's single AWF enclave backend.
	EnclaveBackend string `json:"enclave_backend"`
	// EnclaveEntryID identifies the enclave entry (frontmatter block) this
	// invocation belongs to.
	EnclaveEntryID string `json:"enclave_entry_id"`
	// InvocationID identifies one bounded enclave invocation.
	InvocationID string `json:"invocation_id"`
	// Repository is the canonical, exact-byte owner/repo selector chosen
	// for this invocation. It must already be canonical: the Store performs
	// no trimming, case folding, Unicode normalization, or URL decoding.
	Repository string `json:"repository"`
	// ToolPolicy must equal ToolPolicyGitHubRepositoryReadV1.
	ToolPolicy string `json:"tool_policy"`
	// SchemaHash is the finite response schema hash approved for this
	// invocation; it must be a member of the envelope's allowed set.
	SchemaHash string `json:"schema_hash"`
	// AdmittedDefaultBranchSHA is the default-branch SHA AWF resolved
	// during live-read admission, when known at request time.
	AdmittedDefaultBranchSHA string `json:"admitted_default_branch_sha,omitempty"`
	// RequestedTTL bounds how long the identity should live; it is capped
	// by (and must not exceed) the envelope's MaxIdentityTTL.
	RequestedTTL time.Duration `json:"requested_ttl"`
	// InvocationExpiresAt is the absolute deadline of the invocation, when
	// one is supplied by AWF. An identity can never outlive this deadline.
	InvocationExpiresAt time.Time `json:"invocation_expires_at,omitempty"`
	// IdempotencyKey deduplicates retried create/confirm calls for the same
	// (RunID, EnclaveEntryID, InvocationID, Repository) tuple.
	IdempotencyKey string `json:"idempotency_key"`
}

// Identity is one invocation-scoped delegated identity bound to a single
// canonical repository under github-repository-read-v1.
type Identity struct {
	Handle                   string    `json:"handle"`
	ExecutorBearer           string    `json:"executor_bearer"`
	RunID                    string    `json:"run_id"`
	EnclaveBackend           string    `json:"enclave_backend"`
	EnclaveEntryID           string    `json:"enclave_entry_id"`
	InvocationID             string    `json:"invocation_id"`
	Repository               string    `json:"repository"`
	ToolPolicy               string    `json:"tool_policy"`
	SchemaHash               string    `json:"schema_hash"`
	AdmittedDefaultBranchSHA string    `json:"admitted_default_branch_sha,omitempty"`
	ExpiresAt                time.Time `json:"expires_at"`
	InvocationExpiresAt      time.Time `json:"invocation_expires_at,omitempty"`
	PolicyGeneration         uint64    `json:"policy_generation"`
	IdempotencyKey           string    `json:"idempotency_key"`
	CreatedAt                time.Time `json:"created_at"`
	Revoked                  bool      `json:"revoked"`
}

// invocationScopeKey returns the compound key CreateOrConfirm dedupes on:
// (run, enclave entry, invocation id). The caller-supplied idempotency key is
// intentionally excluded from this key: it is retained on the Identity for
// audit and replay-detection purposes only. Enforcing one identity binding
// per invocation regardless of the idempotency key used to request it is
// required so a caller cannot mint multiple concurrent identities for the
// same invocation merely by varying the idempotency key. The ADR's
// quota/serialization section additionally scopes idempotency by canonical
// repository, but that binding is enforced separately by
// Identity.bindingEquals, which compares the full request (including
// Repository) against any identity already stored under this key and treats
// a mismatch as terminal rather than silently keying on it.
func invocationScopeKey(runID, enclaveEntryID, invocationID string) string {
	return runID + "\x00" + enclaveEntryID + "\x00" + invocationID
}

// labelKey returns the (run, enclave entry) label pair used for bulk revoke
// and restart reconciliation.
func labelKey(runID, enclaveEntryID string) string {
	return runID + "\x00" + enclaveEntryID
}

// IdentityResult is returned to AWF on a successful create or confirm call.
// It intentionally excludes any field not required by the executor: no
// credentials, headers, or repository contents are ever included.
type IdentityResult struct {
	Handle                   string    `json:"handle"`
	ExecutorBearer           string    `json:"executor_bearer"`
	Repository               string    `json:"repository"`
	ToolPolicy               string    `json:"tool_policy"`
	Tools                    []string  `json:"tools"`
	AdmittedDefaultBranchSHA string    `json:"admitted_default_branch_sha,omitempty"`
	ExpiresAt                time.Time `json:"expires_at"`
}

func (id *Identity) toResult() *IdentityResult {
	return &IdentityResult{
		Handle:                   id.Handle,
		ExecutorBearer:           id.ExecutorBearer,
		Repository:               id.Repository,
		ToolPolicy:               id.ToolPolicy,
		Tools:                    DelegatedTools(),
		AdmittedDefaultBranchSHA: id.AdmittedDefaultBranchSHA,
		ExpiresAt:                id.ExpiresAt,
	}
}

// bindingEquals reports whether a repeated create-or-confirm request binds to
// the exact same run, backend, entry, invocation, repository, tool policy,
// schema, and default-branch SHA as the stored identity. A confirm call does
// not get a fresh expiry: the original identity's ExpiresAt (returned by
// toResult) always stands. Per the ADR, any mismatch here is terminal: the
// caller must revoke any partial identity and fail the request.
func (id *Identity) bindingEquals(req CreateOrConfirmRequest) bool {
	return id.RunID == req.RunID &&
		id.EnclaveBackend == req.EnclaveBackend &&
		id.EnclaveEntryID == req.EnclaveEntryID &&
		id.InvocationID == req.InvocationID &&
		id.Repository == req.Repository &&
		id.ToolPolicy == req.ToolPolicy &&
		id.SchemaHash == req.SchemaHash &&
		id.AdmittedDefaultBranchSHA == req.AdmittedDefaultBranchSHA &&
		id.InvocationExpiresAt.Equal(req.InvocationExpiresAt)
}
