package delegation

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/github/gh-aw-mcpg/internal/logger"
)

// captureRecoveryLogs runs f with DEBUG=* and returns what
// logDelegationRecovery wrote to stderr. The logger resolves DEBUG once at
// package initialization, so it must be rebuilt after the environment is set
// or the capture would be empty and every assertion would pass vacuously.
func captureRecoveryLogs(t *testing.T, f func()) string {
	t.Helper()
	t.Setenv("DEBUG", "*")
	t.Setenv("DEBUG_COLORS", "0")

	previous := logDelegationRecovery
	logDelegationRecovery = logger.New("delegation:recovery")
	require.True(t, logDelegationRecovery.Enabled(), "the capture harness must actually enable debug logging")
	t.Cleanup(func() { logDelegationRecovery = previous })

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

// TestLoadStore_FailureLoggingRedactsInvocationScope covers the recovery
// diagnostics themselves. The invocation scope key is built from the run ID,
// enclave entry ID, and invocation ID joined by NUL bytes, so logging it
// verbatim disclosed all three and produced control characters in the log
// file. The same applies to the handle in a duplicate-handle rejection and to
// the repository selector in an envelope-validation rejection.
func TestLoadStore_FailureLoggingRedactsInvocationScope(t *testing.T) {
	now := time.Now()

	duplicateInvocation := []Identity{
		persistedIdentity("dlg_one", "dlgbearer_one", "inv-1", now),
		persistedIdentity("dlg_two", "dlgbearer_two", "inv-1", now),
	}

	duplicateHandle := []Identity{
		persistedIdentity("dlg_same", "dlgbearer_one", "inv-1", now),
		persistedIdentity("dlg_same", "dlgbearer_two", "inv-2", now),
	}

	disallowedRepo := persistedIdentity("dlg_bad", "dlgbearer_bad", "inv-1", now)
	disallowedRepo.Repository = "github/not-allowed"

	cases := []struct {
		name       string
		identities []Identity
	}{
		{"duplicate invocation key", duplicateInvocation},
		{"duplicate handle", duplicateHandle},
		{"envelope validation failure", []Identity{disallowedRepo}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "failure-logging-state.json")
			writePersistedIdentities(t, path, tc.identities...)

			var reloaded *Store
			logs := captureRecoveryLogs(t, func() {
				var err error
				reloaded, err = LoadStore(path, validEnvelope(), 1)
				require.NoError(t, err)
			})
			require.True(t, reloaded.IsRecoveryIncomplete())

			require.Contains(t, logs, "failing closed", "the failure must still be diagnosable")
			assert.NotContains(t, logs, "\x00", "invocation scope keys must never be logged verbatim")
			assert.NotContains(t, logs, "run-123", "the raw run ID must never be logged")
			assert.NotContains(t, logs, "entry-1", "the raw enclave entry ID must never be logged")
			assert.NotContains(t, logs, "github/gh-aw", "the raw repository selector must never be logged")
			for _, id := range tc.identities {
				assert.NotContains(t, logs, id.Handle, "the raw identity handle must never be logged")
				assert.NotContains(t, logs, id.ExecutorBearer, "the raw executor bearer must never be logged")
				assert.NotContains(t, logs, id.InvocationID, "the raw invocation ID must never be logged")
			}
		})
	}
}

// TestSaveAndRevokeLoggingRedactsIdentifiers covers the ordinary revoke and
// successful-recovery paths, which log counts rather than identifiers.
func TestSaveAndRevokeLoggingRedactsIdentifiers(t *testing.T) {
	envelope := validEnvelope()
	store, err := NewStore(envelope, 1)
	require.NoError(t, err)
	created, err := store.CreateOrConfirm(validRequest())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "revoke-logging-state.json")
	require.NoError(t, store.SaveState(path))

	logs := captureRecoveryLogs(t, func() {
		require.NoError(t, store.Revoke(created.Handle))
		require.NoError(t, store.SaveState(path))

		reloaded, err := LoadStore(path, envelope, 1)
		require.NoError(t, err)
		require.False(t, reloaded.IsRecoveryIncomplete())
	})

	assert.NotContains(t, logs, created.Handle, "the raw identity handle must never be logged")
	assert.NotContains(t, logs, created.ExecutorBearer, "the raw executor bearer must never be logged")
	assert.NotContains(t, logs, "\x00", "invocation scope keys must never be logged verbatim")
}
