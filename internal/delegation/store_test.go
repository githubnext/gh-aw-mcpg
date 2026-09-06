package delegation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) (*Store, *Envelope) {
	t.Helper()
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	return store, envelope
}

func validRequest() CreateOrConfirmRequest {
	return CreateOrConfirmRequest{
		RunID:                    "run-123",
		EnclaveBackend:           "awf-enclave",
		EnclaveEntryID:           "entry-1",
		InvocationID:             "inv-1",
		Repository:               "github/gh-aw",
		ToolPolicy:               ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:               "sha256:abc",
		AdmittedDefaultBranchSHA: "deadbeef",
		RequestedTTL:             time.Minute,
		IdempotencyKey:           "idem-1",
	}
}

func TestCreateOrConfirm_CreatesThenConfirmsIdenticalBinding(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)
	assert.NotEmpty(t, created.Handle)
	assert.NotEmpty(t, created.ExecutorBearer)
	assert.Equal(t, "github/gh-aw", created.Repository)
	assert.Equal(t, ToolPolicyGitHubRepositoryReadV1, created.ToolPolicy)
	assert.Equal(t, "deadbeef", created.AdmittedDefaultBranchSHA)
	assert.ElementsMatch(t, []string{"list_issues", "issue_read"}, created.Tools)

	confirmed, err := store.CreateOrConfirm(req)
	require.NoError(t, err)
	assert.Equal(t, created.Handle, confirmed.Handle)
	assert.Equal(t, created.ExecutorBearer, confirmed.ExecutorBearer)
	assert.Equal(t, created.ExpiresAt, confirmed.ExpiresAt)
	assert.Equal(t, created.AdmittedDefaultBranchSHA, confirmed.AdmittedDefaultBranchSHA)
}

func TestCreateOrConfirm_MismatchIsTerminalAndRevokesPartialState(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	mismatched := req
	mismatched.Repository = "github/gh-aw-firewall" // same idempotency key, different repo

	_, err = store.CreateOrConfirm(mismatched)
	require.Error(t, err)

	// The original identity must have been revoked as part of the terminal
	// mismatch, so it can no longer authorize anything.
	require.Error(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"))

	// Replaying the original binding must not silently renew the revoked
	// identity.
	_, err = store.CreateOrConfirm(req)
	assert.Error(t, err)
}

func TestCreateOrConfirm_RejectsOutsideEnvelope(t *testing.T) {
	store, _ := newTestStore(t)

	cases := map[string]func(*CreateOrConfirmRequest){
		"wrong run":         func(r *CreateOrConfirmRequest) { r.RunID = "other-run" },
		"wrong backend":     func(r *CreateOrConfirmRequest) { r.EnclaveBackend = "other-backend" },
		"unlisted repo":     func(r *CreateOrConfirmRequest) { r.Repository = "someone-else/private-repo" },
		"noncanonical repo": func(r *CreateOrConfirmRequest) { r.Repository = "GitHub/gh-aw" },
		"wrong tool policy": func(r *CreateOrConfirmRequest) { r.ToolPolicy = "github-repository-write-v1" },
		"unlisted schema":   func(r *CreateOrConfirmRequest) { r.SchemaHash = "sha256:unknown" },
		"ttl over cap":      func(r *CreateOrConfirmRequest) { r.RequestedTTL = time.Hour },
		"missing entry id":  func(r *CreateOrConfirmRequest) { r.EnclaveEntryID = "" },
		"missing idem key":  func(r *CreateOrConfirmRequest) { r.IdempotencyKey = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := validRequest()
			mutate(&req)
			_, err := store.CreateOrConfirm(req)
			assert.Error(t, err, "expected request outside envelope to be denied")
		})
	}
}

func TestCreateOrConfirm_ConcurrentSameKeyIsAtomic(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	const n = 50
	handles := make([]string, n)
	errs := make([]error, n)
	done := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			result, err := store.CreateOrConfirm(req)
			errs[i] = err
			if err == nil {
				handles[i] = result.Handle
			}
			done <- i
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
	}
	first := handles[0]
	for i := 1; i < n; i++ {
		assert.Equal(t, first, handles[i], "concurrent create/confirm for the same key must converge on one identity")
	}
}

func TestCreateOrConfirm_DifferentIdempotencyKeysSameInvocationConfirmsInsteadOfDuplicating(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	retry := req
	retry.IdempotencyKey = "a-completely-different-idempotency-key"
	confirmed, err := store.CreateOrConfirm(retry)
	require.NoError(t, err, "a retry for the same invocation with a different idempotency key must confirm, not error")
	assert.Equal(t, created.Handle, confirmed.Handle, "one invocation must never produce a second identity merely because the idempotency key changed")
	assert.Equal(t, created.ExecutorBearer, confirmed.ExecutorBearer)
}

func TestCreateOrConfirm_DifferentIdempotencyKeyWithMismatchedBindingIsTerminal(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	mismatched := req
	mismatched.IdempotencyKey = "a-different-key"
	mismatched.Repository = "github/gh-aw-firewall" // different binding, different idempotency key

	_, err = store.CreateOrConfirm(mismatched)
	require.Error(t, err, "a mismatched binding must be denied even under a different idempotency key")

	require.Error(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"),
		"the original identity must have been revoked as part of the terminal mismatch")
}

func TestCreateOrConfirm_BoundedDynamicSchemaHashAdmission(t *testing.T) {
	envelope := validEnvelope()
	envelope.AllowedSchemaHashes = nil
	envelope.MaxDynamicSchemaHashes = 2
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	first := validRequest()
	first.SchemaHash = "sha256:dynamic-1"
	_, err = store.CreateOrConfirm(first)
	require.NoError(t, err)

	second := validRequest()
	second.InvocationID = "inv-2"
	second.IdempotencyKey = "idem-2"
	second.SchemaHash = "sha256:dynamic-2"
	_, err = store.CreateOrConfirm(second)
	require.NoError(t, err)

	// A third distinct schema hash exceeds the bound and must be denied.
	third := validRequest()
	third.InvocationID = "inv-3"
	third.IdempotencyKey = "idem-3"
	third.SchemaHash = "sha256:dynamic-3"
	_, err = store.CreateOrConfirm(third)
	require.Error(t, err, "a third distinct dynamic schema hash must exceed the bound")

	// Reusing an already-admitted hash for a new invocation still works: the
	// bound is on distinct hashes, not on identities.
	fourth := validRequest()
	fourth.InvocationID = "inv-4"
	fourth.IdempotencyKey = "idem-4"
	fourth.SchemaHash = "sha256:dynamic-1"
	_, err = store.CreateOrConfirm(fourth)
	assert.NoError(t, err)
}

func TestAuthorize_RejectsWrongRepoWrongToolWrongRunAndReplay(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()
	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	assert.NoError(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"))
	require.Error(t, store.Authorize(created.Handle, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"), "control-plane handles must not authorize executor requests")
	require.Error(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, "github/gh-aw-firewall", "issue_read"), "wrong repository must be rejected")
	require.Error(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "list_repositories"), "wrong/unscoped tool must be rejected")
	require.Error(t, store.Authorize(created.ExecutorBearer, "other-run", req.EnclaveBackend, req.Repository, "issue_read"), "wrong run must be rejected")
	require.Error(t, store.Authorize("unknown-bearer", req.RunID, req.EnclaveBackend, req.Repository, "issue_read"), "unknown/replayed bearer must be rejected")

	require.NoError(t, store.Revoke(created.Handle))
	assert.Error(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"), "revoked identity must be rejected")
}

func TestAuthorizeExecutor_ReturnsIdentityHandleForIsolation(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()
	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	handle, err := store.AuthorizeExecutor(created.ExecutorBearer, req.Repository, "issue_read")
	require.NoError(t, err)
	assert.Equal(t, created.Handle, handle, "AuthorizeExecutor must expose the identity's own handle so callers can bind a delegation-specific isolation context instead of falling back to a shared identity")

	_, err = store.AuthorizeExecutor("unknown-bearer", req.Repository, "issue_read")
	assert.Error(t, err)
}

func TestExpiry_AutomaticAndExplicit(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	base := time.Now()
	created, err := store.createOrConfirmAt(req, base)
	require.NoError(t, err)

	// Well before expiry: still authorized.
	assert.NoError(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"))

	// After the TTL elapses, cleanup happens lazily on the next store access.
	// Expiry is terminal for this idempotency key and cannot renew the
	// delegation.
	_, err = store.createOrConfirmAt(validRequest(), base.Add(2*time.Minute))
	require.Error(t, err)

	err = store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read")
	assert.Error(t, err, "expired identity must not continue a session")
}

func TestNewStore_ClonesAllowedOwnersDefensively(t *testing.T) {
	envelope := validEnvelope()
	envelope.AllowedOwners = []string{"github"}
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	// Mutate the original slice passed to NewStore
	envelope.AllowedOwners[0] = "mutated-owner"

	// The store's internal copy must remain "github"
	req := validRequest()
	req.Repository = "github/gh-aw"
	_, err = store.CreateOrConfirm(req)
	require.NoError(t, err, "mutating original envelope.AllowedOwners must not affect store policy")

	reqMutated := validRequest()
	reqMutated.InvocationID = "inv-2"
	reqMutated.IdempotencyKey = "idem-2"
	reqMutated.Repository = "mutated-owner/repo"
	_, err = store.CreateOrConfirm(reqMutated)
	assert.Error(t, err, "mutated owner must not be admitted by store")
}

func TestRevoke_IsIdempotent(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()
	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	require.NoError(t, store.Revoke(created.Handle))
	require.NoError(t, store.Revoke(created.Handle)) // second revoke of same handle must not error
	require.NoError(t, store.Revoke("never-existed"))
}

func TestRevokeByLabels_RevokesAllMatchingAndIsIdempotent(t *testing.T) {
	store, _ := newTestStore(t)

	reqA := validRequest()
	reqA.InvocationID = "inv-a"
	reqA.IdempotencyKey = "idem-a"
	createdA, err := store.CreateOrConfirm(reqA)
	require.NoError(t, err)

	reqB := validRequest()
	reqB.InvocationID = "inv-b"
	reqB.IdempotencyKey = "idem-b"
	createdB, err := store.CreateOrConfirm(reqB)
	require.NoError(t, err)

	count := store.RevokeByLabels(reqA.RunID, reqA.EnclaveEntryID)
	assert.Equal(t, 2, count)
	require.Error(t, store.Authorize(createdA.ExecutorBearer, reqA.RunID, reqA.EnclaveBackend, reqA.Repository, "issue_read"))
	require.Error(t, store.Authorize(createdB.ExecutorBearer, reqB.RunID, reqB.EnclaveBackend, reqB.Repository, "issue_read"))

	// Idempotent: revoking an already-empty label is a no-op, not an error.
	assert.Equal(t, 0, store.RevokeByLabels(reqA.RunID, reqA.EnclaveEntryID))
}

func TestCreateOrConfirm_RecoveryIncompleteBlocksNewAdmissionsOnly(t *testing.T) {
	store, _ := newTestStore(t)
	req := validRequest()

	// Pre-existing identity (as if reconstructed from disk).
	existing, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	store.mu.Lock()
	store.recoveryIncomplete = true
	store.mu.Unlock()

	// Confirming the already-known identity must still succeed.
	confirmed, err := store.CreateOrConfirm(req)
	require.NoError(t, err)
	assert.Equal(t, existing.Handle, confirmed.Handle)

	// But a brand-new admission must fail closed until reconciliation.
	newReq := validRequest()
	newReq.InvocationID = "inv-new"
	newReq.IdempotencyKey = "idem-new"
	_, err = store.CreateOrConfirm(newReq)
	require.Error(t, err)

	store.MarkReconciled()
	assert.False(t, store.IsRecoveryIncomplete())
	_, err = store.CreateOrConfirm(newReq)
	assert.NoError(t, err)
}

func TestCreateOrConfirm_EnvelopeExpiredDeniesEverything(t *testing.T) {
	envelope := validEnvelope()
	envelope.ExpiresAt = time.Now().Add(-time.Minute)
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	_, err = store.CreateOrConfirm(validRequest())
	assert.Error(t, err)
}

func TestCreateOrConfirm_BoundsExpiryToPolicyAndInvocationDeadlines(t *testing.T) {
	envelope := validEnvelope()
	base := time.Now()
	envelope.ExpiresAt = base.Add(30 * time.Second)
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	req := validRequest()
	req.RequestedTTL = time.Minute
	req.InvocationExpiresAt = base.Add(10 * time.Second)
	created, err := store.createOrConfirmAt(req, base)
	require.NoError(t, err)
	assert.Equal(t, req.InvocationExpiresAt, created.ExpiresAt)

	// The store owns an immutable copy of the compiler envelope.
	envelope.ExpiresAt = base.Add(-time.Second)
	assert.NoError(t, store.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"))
}
