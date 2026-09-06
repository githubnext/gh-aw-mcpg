package sanitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withRedaction enables private-selector redaction for the duration of the
// test and restores the previous process-wide mode afterwards.
func withRedaction(t *testing.T) {
	t.Helper()
	previous := PrivateSelectorRedactionEnabled()
	SetPrivateSelectorRedaction(true)
	t.Cleanup(func() { SetPrivateSelectorRedaction(previous) })
}

func TestRedactPrivateSelectors(t *testing.T) {
	const (
		owner   = "octo-secret"
		repo    = "private-repo"
		runID   = "run-9876543210"
		entryID = "entry-abcdef"
	)

	cases := []struct {
		name    string
		message string
	}{
		{"rest path", "forwardAndReadBody: GET /repos/octo-secret/private-repo/issues/7"},
		{"rest path with query", "passthrough GET /repos/octo-secret/private-repo/issues?state=open"},
		{"rest path root", "restBackendCaller: get_issue → GET /repos/octo-secret/private-repo"},
		{"quoted rest path", `upstream request failed: GET "/repos/octo-secret/private-repo/pulls/3": dial tcp: refused`},
		{"secrecy tag", "[DIFC] Phase 1: secrecy=[private:octo-secret/private-repo] integrity=[]"},
		{"guard resource description", "[DIFC] Phase 1: resource=issue:octo-secret/private-repo#7 op=read"},
		{"pull request description", "resource=pr:octo-secret/private-repo#3"},
		{"search qualifier", "query=repo:octo-secret/private-repo is:open"},
		{"route match", "Route matched successfully: operation=issue_read, repo=octo-secret/private-repo"},
		{"normalization failure", "Repository normalization failed or mismatched: repo=octo-secret/private-repo, valid=false"},
		{"quoted envelope validation error", `envelope must not contain duplicate repository "octo-secret/private-repo"`},
		{"run identifier", "Created enclave capability verifier: run=run-9876543210, profile=github"},
		{"entry identifier", "delegating request: enclave_entry_id=entry-abcdef"},
		{"invocation identifier", "Verified enclave capability: invocation=run-9876543210"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redacted := RedactPrivateSelectors(tc.message)
			assert.NotContains(t, redacted, owner, "owner must not survive redaction")
			assert.NotContains(t, redacted, repo, "repository must not survive redaction")
			assert.NotContains(t, redacted, runID, "run identifier must not survive redaction")
			assert.NotContains(t, redacted, entryID, "enclave entry identifier must not survive redaction")
			assert.NotEqual(t, tc.message, redacted, "a sensitive message must actually change")
		})
	}
}

// TestRedactPrivateSelectorsIsStableAndIdempotent pins the two properties that
// keep redacted logs useful: the same input always renders as the same token,
// so lines can still be correlated, and re-running redaction over already
// redacted output does not churn the token.
func TestRedactPrivateSelectorsIsStableAndIdempotent(t *testing.T) {
	message := "forwardAndReadBody: GET /repos/octo-secret/private-repo/issues/7 -> status=200"

	first := RedactPrivateSelectors(message)
	second := RedactPrivateSelectors(message)
	require.Equal(t, first, second, "redaction must be deterministic")
	assert.Equal(t, first, RedactPrivateSelectors(first), "redaction must be idempotent")

	other := RedactPrivateSelectors("forwardAndReadBody: GET /repos/octo-secret/other-repo/issues/7 -> status=200")
	assert.NotEqual(t, first, other, "distinct selectors must render as distinct tokens")
}

func TestRedactPrivateSelectorsLeavesNonSelectorTextIntact(t *testing.T) {
	message := "Reconstructed delegation state: restored=3 of 4 persisted identities"
	assert.Equal(t, message, RedactPrivateSelectors(message))

	statusLine := "forwardAndReadBody: GET -> status=404 bodyLen=27"
	assert.Equal(t, statusLine, RedactPrivateSelectors(statusLine))
}

// TestSanitizeStringRedactsOnlyWhenEnabled proves the shared sink hook works:
// every file-backed log sink formats through SanitizeString, so enabling the
// mode protects mcp-gateway.log, the per-server logs, the markdown log, and
// the RPC JSONL log without touching any of their call sites.
func TestSanitizeStringRedactsOnlyWhenEnabled(t *testing.T) {
	message := "forwardAndReadBody: GET /repos/octo-secret/private-repo/issues/7"

	require.False(t, PrivateSelectorRedactionEnabled(), "redaction must be off by default")
	assert.Contains(t, SanitizeString(message), "/repos/octo-secret/private-repo/issues/7",
		"ordinary deployments must keep readable diagnostics")

	withRedaction(t)
	sanitized := SanitizeString(message)
	assert.NotContains(t, sanitized, "octo-secret")
	assert.NotContains(t, sanitized, "private-repo")
}

// TestSanitizeStringStillRedactsSecretsUnderRedactionMode guards against the
// selector pass swallowing or bypassing the pre-existing secret redaction.
func TestSanitizeStringStillRedactsSecretsUnderRedactionMode(t *testing.T) {
	withRedaction(t)

	sanitized := SanitizeString("authorization=ghp_0123456789abcdefghijklmnopqrstuvwxyz path=/repos/octo-secret/private-repo")
	assert.NotContains(t, sanitized, "ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	assert.NotContains(t, sanitized, "private-repo")
}
