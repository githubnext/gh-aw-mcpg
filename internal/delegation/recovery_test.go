package delegation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadStore_RoundTripsLiveIdentities(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 7)
	require.NoError(t, err)

	req := validRequest()
	req.RequestedTTL = 2 * time.Minute
	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "delegation-state.json")
	require.NoError(t, store.SaveState(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "state file must not be group/world readable: it contains executor bearer secrets")

	reloaded, err := LoadStore(path, envelope, 7)
	require.NoError(t, err)
	assert.False(t, reloaded.IsRecoveryIncomplete())

	// The reconstructed identity must confirm to the exact same handle and
	// bearer for a repeated create-or-confirm call.
	confirmed, err := reloaded.CreateOrConfirm(req)
	require.NoError(t, err)
	assert.Equal(t, created.Handle, confirmed.Handle)
	assert.Equal(t, created.ExecutorBearer, confirmed.ExecutorBearer)

	assert.NoError(t, reloaded.Authorize(created.ExecutorBearer, req.RunID, req.EnclaveBackend, req.Repository, "issue_read"))
}

func TestLoadStore_NoPriorFileIsFreshStartNotIncomplete(t *testing.T) {
	envelope := validEnvelope()
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	store, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.False(t, store.IsRecoveryIncomplete(), "a fresh gateway with no prior state has nothing to reconcile")

	_, err = store.CreateOrConfirm(validRequest())
	assert.NoError(t, err)
}

func TestLoadStore_CorruptFileFailsClosed(t *testing.T) {
	envelope := validEnvelope()
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt-state.json")
	require.NoError(t, os.WriteFile(path, []byte("not valid json at all\n"), 0o600))

	store, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.True(t, store.IsRecoveryIncomplete(), "corrupt state must fail closed rather than silently reconstruct partial state")

	_, err = store.CreateOrConfirm(validRequest())
	assert.Error(t, err, "new admissions must be refused until reconciliation succeeds")
}

func TestLoadStore_TruncatedChecksumFailsClosed(t *testing.T) {
	envelope := validEnvelope()
	dir := t.TempDir()
	path := filepath.Join(dir, "truncated-state.json")

	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	_, err = store.CreateOrConfirm(validRequest())
	require.NoError(t, err)
	require.NoError(t, store.SaveState(path))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// Truncate mid-file to simulate a crash during write.
	require.NoError(t, os.WriteFile(path, raw[:len(raw)/2], 0o600))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete())
}

func TestLoadStore_DropsAlreadyExpiredIdentitiesSilently(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	req := validRequest()
	req.RequestedTTL = time.Second
	_, err = store.createOrConfirmAt(req, time.Now().Add(-time.Hour))
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	require.NoError(t, store.SaveState(path))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.False(t, reloaded.IsRecoveryIncomplete(), "naturally expired identities are not a reconciliation failure")

	// Expiry tombstones prevent a stale idempotency key from renewing a
	// delegation after restart.
	_, err = reloaded.CreateOrConfirm(req)
	assert.Error(t, err)
}

func TestLoadStore_RejectsGenerationAndEnvelopeMismatches(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	_, err = store.CreateOrConfirm(validRequest())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, store.SaveState(path))

	reloaded, err := LoadStore(path, envelope, 2)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete())

	require.NoError(t, store.SaveState(path))
	narrowed := validEnvelope()
	narrowed.AllowedRepositories = []string{"github/other"}
	reloaded, err = LoadStore(path, narrowed, 1)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete())
}

func TestLoadStore_FailsClosedOnLegacyVersion(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	_, err = store.CreateOrConfirm(validRequest())
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-v1-state.json")

	// Construct a legacy version 1 state file payload
	now := time.Now()
	id := Identity{
		Handle:              "dlg_legacy123",
		ExecutorBearer:      "dlgbearer_legacy123",
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        "inv-1",
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-1",
		CreatedAt:           now,
	}
	body := fmt.Sprintf(`{"version":1,"generation":1,"recovery_incomplete":false,"identities":{"dlg_legacy123":%s}}`, marshalJSON(id))
	writeStateWithChecksum(t, path, []byte(body))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete(), "legacy v1 state file must fail closed")
}

func TestLoadStore_FailsClosedOnDuplicateLiveInvocationKeys(t *testing.T) {
	envelope := validEnvelope()
	dir := t.TempDir()
	path := filepath.Join(dir, "duplicate-keys-state.json")

	now := time.Now()
	id1 := Identity{
		Handle:              "dlg_handle1",
		ExecutorBearer:      "dlgbearer_bearer1",
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        "inv-1",
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-1",
		CreatedAt:           now,
	}
	id2 := Identity{
		Handle:              "dlg_handle2",
		ExecutorBearer:      "dlgbearer_bearer2",
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        "inv-1", // same invocation ID
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-2",
		CreatedAt:           now,
	}

	body := fmt.Sprintf(`{"version":2,"generation":1,"recovery_incomplete":false,"identities":{"h1":%s,"h2":%s}}`, marshalJSON(id1), marshalJSON(id2))
	writeStateWithChecksum(t, path, []byte(body))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete(), "duplicate live invocation keys must fail closed")
	assert.Empty(t, reloaded.byHandle, "no identity may be indexed when recovery fails closed")
	assert.Empty(t, reloaded.byBearer, "no bearer may be indexed when recovery fails closed")
	assert.Empty(t, reloaded.byInvocation, "no invocation tombstone may be indexed when recovery fails closed")
}

// TestLoadStore_FailsClosedOnDuplicateLiveAndTerminalInvocationKeys covers a
// duplicate invocation key where one persisted record is live and the other
// is already terminal (revoked or expired). Map iteration order is
// randomized, so a naive "only check the current winner" comparison could
// index the live identity first, before ever observing the terminal
// duplicate, leaving an authorized orphan bearer reachable after restart in
// one iteration order but not the other. Every duplicate must fail closed
// with nothing indexed, regardless of iteration order or liveness.
func TestLoadStore_FailsClosedOnDuplicateLiveAndTerminalInvocationKeys(t *testing.T) {
	envelope := validEnvelope()
	dir := t.TempDir()
	path := filepath.Join(dir, "duplicate-live-terminal-state.json")

	now := time.Now()
	live := Identity{
		Handle:              "dlg_live",
		ExecutorBearer:      "dlgbearer_live",
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        "inv-1",
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-1",
		CreatedAt:           now,
	}
	terminal := Identity{
		Handle:              "dlg_terminal",
		ExecutorBearer:      "dlgbearer_terminal",
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        "inv-1", // same invocation ID
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-2",
		CreatedAt:           now,
		Revoked:             true,
	}

	body := fmt.Sprintf(`{"version":2,"generation":1,"recovery_incomplete":false,"identities":{"h1":%s,"h2":%s}}`, marshalJSON(live), marshalJSON(terminal))
	writeStateWithChecksum(t, path, []byte(body))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete(), "duplicate live/terminal invocation keys must fail closed")
	assert.Empty(t, reloaded.byHandle, "no identity may be indexed when recovery fails closed")
	assert.Empty(t, reloaded.byBearer, "no bearer may be indexed when recovery fails closed")
	assert.Empty(t, reloaded.byInvocation, "no invocation tombstone may be indexed when recovery fails closed")

	if _, err := reloaded.AuthorizeExecutor("dlgbearer_live", "github/gh-aw", "issue_read"); err == nil {
		t.Fatal("the live half of a duplicate pair must not remain an authorized orphan bearer")
	}
}

func marshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeStateWithChecksum(t *testing.T, path string, body []byte) {
	t.Helper()
	checksum := sha256.Sum256(body)
	out := append(body, []byte("\n"+hex.EncodeToString(checksum[:])+"\n")...)
	require.NoError(t, os.WriteFile(path, out, 0o600))
}

func TestSaveState_ReplacesExistingPermissions(t *testing.T) {
	store, _ := newTestStore(t)
	_, err := store.CreateOrConfirm(validRequest())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte("insecure"), 0o644))
	require.NoError(t, store.SaveState(path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestLoadStore_RepairsLabelIndexForRestoredTerminalIdentities(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	req := validRequest()
	created, err := store.CreateOrConfirm(req)
	require.NoError(t, err)
	// Revoking leaves a terminal tombstone under the same (run, enclave
	// entry, invocation) key, which is what gets persisted and restored.
	require.NoError(t, store.Revoke(created.Handle))

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, store.SaveState(path))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assert.False(t, reloaded.IsRecoveryIncomplete())

	// Before the fix, restoring an already-terminal identity added it to
	// byLabel (via indexLocked) but only removed it from byHandle/byBearer,
	// leaving a dangling byLabel entry with no corresponding byHandle entry.
	// RevokeByLabels would then dereference that missing handle and panic.
	assert.NotPanics(t, func() {
		assert.Equal(t, 0, reloaded.RevokeByLabels(req.RunID, req.EnclaveEntryID), "the tombstoned identity is no longer live or labelled")
	})
	assert.Empty(t, reloaded.byLabel, "the label index must not retain a restored terminal identity")
}

func TestLoadStore_RestoresDynamicSchemaHashBound(t *testing.T) {
	envelope := validEnvelope()
	envelope.AllowedSchemaHashes = nil
	envelope.MaxDynamicSchemaHashes = 1
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)

	req := validRequest()
	req.SchemaHash = "sha256:dynamic-only"
	_, err = store.CreateOrConfirm(req)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, store.SaveState(path))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)

	// The bound was already exhausted by the persisted hash, so a
	// brand-new distinct hash must still be denied after restart.
	other := validRequest()
	other.InvocationID = "inv-other"
	other.IdempotencyKey = "idem-other"
	other.SchemaHash = "sha256:another-dynamic"
	_, err = reloaded.CreateOrConfirm(other)
	require.Error(t, err, "the dynamic schema hash bound must not reset across a restart")

	// But the already-admitted hash still works for a new invocation.
	reuse := validRequest()
	reuse.InvocationID = "inv-reuse"
	reuse.IdempotencyKey = "idem-reuse"
	reuse.SchemaHash = "sha256:dynamic-only"
	_, err = reloaded.CreateOrConfirm(reuse)
	assert.NoError(t, err)
}

func TestSaveState_ConcurrentCallsRemainConsistent(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "state.json")

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := validRequest()
			req.InvocationID = fmt.Sprintf("inv-%d", i)
			req.IdempotencyKey = fmt.Sprintf("idem-%d", i)
			_, err := store.CreateOrConfirm(req)
			assert.NoError(t, err)
			assert.NoError(t, store.SaveState(path))
		}(i)
	}
	wg.Wait()

	// A final save after every concurrent create must capture every
	// identity: concurrent SaveState calls must never corrupt the file or
	// leave it holding a stale, already-superseded snapshot.
	require.NoError(t, store.SaveState(path))
	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	require.False(t, reloaded.IsRecoveryIncomplete())

	for i := 0; i < n; i++ {
		req := validRequest()
		req.InvocationID = fmt.Sprintf("inv-%d", i)
		req.IdempotencyKey = fmt.Sprintf("idem-%d", i)
		_, err := reloaded.CreateOrConfirm(req)
		assert.NoError(t, err, "identity for invocation %d must have survived concurrent persistence", i)
	}
}

// persistedIdentity builds a live identity that validates against
// validEnvelope() so tests only need to vary the fields under test.
func persistedIdentity(handle, bearer, invocationID string, now time.Time) Identity {
	return Identity{
		Handle:              handle,
		ExecutorBearer:      bearer,
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		EnclaveEntryID:      "entry-1",
		InvocationID:        invocationID,
		Repository:          "github/gh-aw",
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		SchemaHash:          "sha256:abc",
		ExpiresAt:           now.Add(time.Hour),
		InvocationExpiresAt: now.Add(time.Hour),
		PolicyGeneration:    1,
		IdempotencyKey:      "idem-" + handle,
		CreatedAt:           now,
	}
}

// writePersistedIdentities writes a checksummed current-version state file
// containing identities, keyed by idempotency key exactly as SaveState would
// key them if the file had been produced before duplicate detection existed.
func writePersistedIdentities(t *testing.T, path string, identities ...Identity) {
	t.Helper()
	entries := make([]string, 0, len(identities))
	for i, id := range identities {
		entries = append(entries, fmt.Sprintf(`%q:%s`, fmt.Sprintf("k%d", i), marshalJSON(id)))
	}
	body := fmt.Sprintf(`{"version":2,"generation":1,"recovery_incomplete":false,"identities":{%s}}`, strings.Join(entries, ","))
	writeStateWithChecksum(t, path, []byte(body))
}

// assertFailedClosedRecovery asserts the complete fail-closed contract: the
// store reports incomplete recovery, holds zero identities in every index, and
// refuses both new admissions and data-plane authorization for every bearer
// that appeared in the rejected state file.
func assertFailedClosedRecovery(t *testing.T, store *Store, bearers ...string) {
	t.Helper()
	assert := assert.New(t)
	require := require.New(t)

	assert.True(store.IsRecoveryIncomplete(), "recovery must be reported incomplete")
	assert.Zero(store.Status().LiveIdentityCount, "a failed recovery must restore zero live identities")
	assert.Empty(store.byHandle, "no identity may be indexed when recovery fails closed")
	assert.Empty(store.byBearer, "no bearer may be indexed when recovery fails closed")
	assert.Empty(store.byInvocation, "no invocation tombstone may be indexed when recovery fails closed")
	assert.Empty(store.byLabel, "no label index entry may survive a failed recovery")
	assert.Empty(store.dynamicSchemaHashes, "no dynamic schema hash may be restored from a rejected state file")
	assert.Empty(store.LabelHandles("run-123", "entry-1"), "no labelled handle may survive a failed recovery")

	_, err := store.CreateOrConfirm(validRequest())
	require.Error(err, "new dynamic admissions must be refused while recovery is incomplete")

	for _, bearer := range bearers {
		err := store.Authorize(bearer, "run-123", "awf-enclave", "github/gh-aw", "issue_read")
		require.Errorf(err, "bearer %q from a failed recovery must not authorize", bearer)
		_, err = store.AuthorizeExecutor(bearer, "github/gh-aw", "issue_read")
		require.Errorf(err, "bearer %q from a failed recovery must not authorize an executor call", bearer)
	}
}

// TestLoadStore_FailsClosedOnDuplicateInvocationOrdering drives both possible
// orderings of a live/terminal duplicate pair explicitly. The persisted
// identity map has randomized iteration order, so a loader that indexed as it
// scanned produced a different store depending on which half it saw first:
// live-then-terminal left an authorized orphan bearer behind, while
// terminal-then-live did not. Recovery must fail closed identically in both
// directions and for every liveness combination.
func TestLoadStore_FailsClosedOnDuplicateInvocationOrdering(t *testing.T) {
	now := time.Now()

	live := persistedIdentity("dlg_live", "dlgbearer_live", "inv-1", now)

	revoked := persistedIdentity("dlg_revoked", "dlgbearer_revoked", "inv-1", now)
	revoked.Revoked = true

	expired := persistedIdentity("dlg_expired", "dlgbearer_expired", "inv-1", now)
	expired.ExpiresAt = now.Add(-time.Minute)

	secondRevoked := persistedIdentity("dlg_revoked2", "dlgbearer_revoked2", "inv-1", now)
	secondRevoked.Revoked = true

	cases := []struct {
		name       string
		identities []Identity
	}{
		{"live before revoked", []Identity{live, revoked}},
		{"revoked before live", []Identity{revoked, live}},
		{"live before expired", []Identity{live, expired}},
		{"expired before live", []Identity{expired, live}},
		{"both terminal", []Identity{revoked, secondRevoked}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := validEnvelope()
			path := filepath.Join(t.TempDir(), "duplicate-ordering-state.json")
			writePersistedIdentities(t, path, tc.identities...)

			reloaded, err := LoadStore(path, envelope, 1)
			require.NoError(t, err)

			bearers := make([]string, 0, len(tc.identities))
			for _, id := range tc.identities {
				bearers = append(bearers, id.ExecutorBearer)
			}
			assertFailedClosedRecovery(t, reloaded, bearers...)
		})
	}
}

// TestLoadStore_FailsClosedOnDuplicateHandleOrBearer covers the other two ways
// a crafted or legacy state file can make the in-memory indexes diverge from
// the file: two records sharing a handle collide in byHandle, and two sharing
// an executor bearer collide in byBearer, in both cases silently discarding
// one record while leaving the other authorized.
func TestLoadStore_FailsClosedOnDuplicateHandleOrBearer(t *testing.T) {
	now := time.Now()

	t.Run("duplicate handle", func(t *testing.T) {
		first := persistedIdentity("dlg_same", "dlgbearer_one", "inv-1", now)
		second := persistedIdentity("dlg_same", "dlgbearer_two", "inv-2", now)

		path := filepath.Join(t.TempDir(), "duplicate-handle-state.json")
		writePersistedIdentities(t, path, first, second)

		reloaded, err := LoadStore(path, validEnvelope(), 1)
		require.NoError(t, err)
		assertFailedClosedRecovery(t, reloaded, "dlgbearer_one", "dlgbearer_two")
	})

	t.Run("duplicate executor bearer", func(t *testing.T) {
		first := persistedIdentity("dlg_one", "dlgbearer_same", "inv-1", now)
		second := persistedIdentity("dlg_two", "dlgbearer_same", "inv-2", now)

		path := filepath.Join(t.TempDir(), "duplicate-bearer-state.json")
		writePersistedIdentities(t, path, first, second)

		reloaded, err := LoadStore(path, validEnvelope(), 1)
		require.NoError(t, err)
		assertFailedClosedRecovery(t, reloaded, "dlgbearer_same")
	})
}

// TestLoadStore_FailsClosedDiscardsAlreadyScannedIdentities pins the ordering
// property directly: several perfectly valid identities precede the corrupt
// one in handle order, so a loader that indexed as it scanned would leave them
// live. None of their bearers may authorize.
func TestLoadStore_FailsClosedDiscardsAlreadyScannedIdentities(t *testing.T) {
	now := time.Now()
	good1 := persistedIdentity("dlg_aaa", "dlgbearer_aaa", "inv-1", now)
	good2 := persistedIdentity("dlg_bbb", "dlgbearer_bbb", "inv-2", now)
	good3 := persistedIdentity("dlg_ccc", "dlgbearer_ccc", "inv-3", now)
	// Invalid: bound to a repository the active envelope does not allow.
	bad := persistedIdentity("dlg_zzz", "dlgbearer_zzz", "inv-4", now)
	bad.Repository = "github/not-allowed"

	path := filepath.Join(t.TempDir(), "partial-scan-state.json")
	writePersistedIdentities(t, path, good1, good2, good3, bad)

	reloaded, err := LoadStore(path, validEnvelope(), 1)
	require.NoError(t, err)
	assertFailedClosedRecovery(t, reloaded,
		"dlgbearer_aaa", "dlgbearer_bbb", "dlgbearer_ccc", "dlgbearer_zzz")
}

// TestLoadStore_FailsClosedOnPersistedDynamicSchemaHashViolations rejects a
// dynamic schema hash set the active envelope would never have admitted.
// Restoring it would silently widen the runtime schema bound CreateOrConfirm
// enforces, and would leave the in-memory bound diverged from the envelope.
func TestLoadStore_FailsClosedOnPersistedDynamicSchemaHashViolations(t *testing.T) {
	t.Run("set under a closed-set envelope", func(t *testing.T) {
		envelope := validEnvelope() // AllowedSchemaHashes is non-empty
		path := filepath.Join(t.TempDir(), "static-envelope-state.json")
		body := `{"version":2,"generation":1,"recovery_incomplete":false,"identities":{},"dynamic_schema_hashes":["sha256:dynamic"]}`
		writeStateWithChecksum(t, path, []byte(body))

		reloaded, err := LoadStore(path, envelope, 1)
		require.NoError(t, err)
		assert.True(t, reloaded.IsRecoveryIncomplete(), "dynamic hashes under a closed-set envelope must fail closed")
		assert.Empty(t, reloaded.dynamicSchemaHashes)
	})

	t.Run("set wider than the envelope bound", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.AllowedSchemaHashes = nil
		envelope.MaxDynamicSchemaHashes = 1
		path := filepath.Join(t.TempDir(), "oversized-schema-state.json")
		body := `{"version":2,"generation":1,"recovery_incomplete":false,"identities":{},"dynamic_schema_hashes":["sha256:one","sha256:two"]}`
		writeStateWithChecksum(t, path, []byte(body))

		reloaded, err := LoadStore(path, envelope, 1)
		require.NoError(t, err)
		assert.True(t, reloaded.IsRecoveryIncomplete(), "an oversized dynamic hash set must fail closed")
		assert.Empty(t, reloaded.dynamicSchemaHashes)
	})
}

// TestLoadStore_FailsClosedOnLegacyVersionRefusesEveryPersistedBearer extends
// the legacy-version case to the full contract: a v1 file may have been
// written by a build with different invariants, so none of its bearers may
// authorize and nothing may be indexed.
func TestLoadStore_FailsClosedOnLegacyVersionRefusesEveryPersistedBearer(t *testing.T) {
	envelope := validEnvelope()
	path := filepath.Join(t.TempDir(), "legacy-v1-full-state.json")

	id := persistedIdentity("dlg_legacy", "dlgbearer_legacy", "inv-1", time.Now())
	body := fmt.Sprintf(`{"version":1,"generation":1,"recovery_incomplete":false,"identities":{"k0":%s}}`, marshalJSON(id))
	writeStateWithChecksum(t, path, []byte(body))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assertFailedClosedRecovery(t, reloaded, "dlgbearer_legacy")
}

// TestLoadStore_FailsClosedOnGenerationMismatchRefusesPersistedBearer covers a
// state file written under a superseded policy generation.
func TestLoadStore_FailsClosedOnGenerationMismatchRefusesPersistedBearer(t *testing.T) {
	envelope := validEnvelope()
	path := filepath.Join(t.TempDir(), "generation-mismatch-state.json")

	id := persistedIdentity("dlg_stale", "dlgbearer_stale", "inv-1", time.Now())
	body := fmt.Sprintf(`{"version":2,"generation":1,"recovery_incomplete":false,"identities":{"k0":%s}}`, marshalJSON(id))
	writeStateWithChecksum(t, path, []byte(body))

	reloaded, err := LoadStore(path, envelope, 2)
	require.NoError(t, err)
	assert.True(t, reloaded.IsRecoveryIncomplete())
	assert.Zero(t, reloaded.Status().LiveIdentityCount)
	_, err = reloaded.AuthorizeExecutor("dlgbearer_stale", "github/gh-aw", "issue_read")
	require.Error(t, err, "a bearer from a superseded generation must not authorize")
}

// TestLoadStore_CorruptFileRefusesPreCrashBearer confirms the data-plane gate
// covers a bearer that a caller still holds from before the restart, even
// though the corrupt file means the store never learned about it.
func TestLoadStore_CorruptFileRefusesPreCrashBearer(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	created, err := store.CreateOrConfirm(validRequest())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "corrupt-state.json")
	require.NoError(t, os.WriteFile(path, []byte("not json\n"), 0o600))

	reloaded, err := LoadStore(path, envelope, 1)
	require.NoError(t, err)
	assertFailedClosedRecovery(t, reloaded, created.ExecutorBearer)
}
