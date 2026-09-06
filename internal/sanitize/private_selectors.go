package sanitize

import (
	"regexp"
	"sync/atomic"

	"github.com/github/gh-aw-mcpg/internal/util"
)

// Private-selector redaction exists for the enclave and delegation proxy
// profiles. In those profiles every repository the process touches was chosen
// at runtime by a controller (AWF) rather than by the compiler, and the
// selector itself — plus the request path, run, entry, invocation, handle, and
// bearer values bound to it — is the secret being protected. Individual call
// sites already hash the values they know about, but log lines are assembled
// from many packages (route matching, tracing, the DIFC pipeline, upstream
// forwarding, wrapped error strings), and any one of them that forgets would
// silently disclose the selector under DEBUG=*.
//
// Redacting at the shared sink closes that class of gap: once
// EnablePrivateSelectorRedaction is called, every formatted log line — debug
// output on stderr, mcp-gateway.log, the per-server logs, the markdown log,
// and the RPC JSONL log — is rewritten to replace selectors and paths with
// stable, non-reversible hashes. Diagnostics stay correlatable across lines
// because the same input always renders as the same token.

var privateSelectorRedaction atomic.Bool

// EnablePrivateSelectorRedaction turns on process-wide redaction of private
// repository selectors, request paths, and runtime delegation identifiers in
// every sanitized log sink. It is called once during proxy startup for the
// enclave and delegation profiles and is safe for concurrent use.
func EnablePrivateSelectorRedaction() {
	privateSelectorRedaction.Store(true)
}

// SetPrivateSelectorRedaction sets the redaction mode explicitly. It exists so
// tests can restore the previous mode; production code should call
// EnablePrivateSelectorRedaction.
func SetPrivateSelectorRedaction(enabled bool) {
	privateSelectorRedaction.Store(enabled)
}

// PrivateSelectorRedactionEnabled reports whether private-selector redaction
// is active for this process.
func PrivateSelectorRedactionEnabled() bool {
	return privateSelectorRedaction.Load()
}

// selectorSegment matches one owner or repository name segment. GitHub login
// and repository names are limited to these characters, so the pattern cannot
// swallow surrounding punctuation, quotes, or whitespace from a log line.
const selectorSegment = `[A-Za-z0-9._-]+`

var (
	// repoAPIPathRe matches a REST path rooted at a repository selector, such
	// as "/repos/owner/private-repo/issues/12". The selector is replaced and
	// the remainder of the path is dropped, because path tails carry issue,
	// pull request, and ref identifiers that are equally invocation-scoped.
	repoAPIPathRe = regexp.MustCompile(`/repos/` + selectorSegment + `/` + selectorSegment + `(/[^\s"'\x60,)\]}]*)?`)

	// labelledSelectorRe matches the "<label>:<owner>/<repo>" form used by
	// DIFC secrecy/integrity tags (private:owner/repo), guard resource
	// descriptions (issue:owner/repo#10, pr:owner/repo#3, file:owner/repo),
	// and GitHub search qualifiers (repo:owner/repo).
	labelledSelectorRe = regexp.MustCompile(`\b(private|public|repo|repository|issue|pr|file|discussion|release|commit|branch|tag|fork|star|watch)\s*:\s*` + selectorSegment + `/` + selectorSegment + `(#\d+)?`)

	// keyedSelectorRe matches "repo=owner/name", "repository: owner/name",
	// and the quoted `repository "owner/name"` rendering that %q produces in
	// envelope validation errors.
	keyedSelectorRe = regexp.MustCompile(`(?i)\b(repo|repos|repository|full_repo|fullrepo|assigned_repo|selector)\s*(?:[=:]\s*|\s+)"?` + selectorSegment + `/` + selectorSegment + `"?`)

	// runIdentifierRe matches the runtime delegation identifiers that scope a
	// selector to one invocation. On their own they are not repository names,
	// but they let an observer correlate a redacted selector back to the
	// workflow run, enclave entry, or invocation that admitted it.
	runIdentifierRe = regexp.MustCompile(`(?i)\b(run|run_id|runid|workflow_run_id|enclave_entry_id|entry_id|invocation|invocation_id|idempotency_key)\s*[=:]\s*"?[A-Za-z0-9._:@/-]+"?`)
)

// RedactPrivateSelectors rewrites every private repository selector, repository
// API path, and runtime delegation identifier in message with a stable,
// non-reversible hash. It always redacts, regardless of the process-wide mode,
// so callers that know a value is sensitive can use it directly.
func RedactPrivateSelectors(message string) string {
	result := repoAPIPathRe.ReplaceAllStringFunc(message, func(match string) string {
		return "/repos/" + util.HashForLog(match, 16, "path:")
	})
	result = replaceKeyed(result, labelledSelectorRe, "sel:")
	result = replaceKeyed(result, keyedSelectorRe, "sel:")
	result = replaceKeyed(result, runIdentifierRe, "id:")
	return result
}

// replaceKeyed rewrites every match of re as "<key>=<hash>", where the key is
// re's first capture group. Keeping the key makes redacted lines readable
// ("repo=sel:..." rather than an unattributed token) while the hash keeps the
// value non-reversible but stable across lines.
func replaceKeyed(message string, re *regexp.Regexp, prefix string) string {
	return re.ReplaceAllStringFunc(message, func(match string) string {
		groups := re.FindStringSubmatch(match)
		if len(groups) < 2 {
			return util.HashForLog(match, 16, prefix)
		}
		return groups[1] + "=" + util.HashForLog(match, 16, prefix)
	})
}

// RedactPrivateSelectorsIfEnabled applies RedactPrivateSelectors only when the
// process-wide mode is active. Non-enclave, non-delegation deployments keep
// their existing, fully readable diagnostics.
func RedactPrivateSelectorsIfEnabled(message string) string {
	if !privateSelectorRedaction.Load() {
		return message
	}
	return RedactPrivateSelectors(message)
}
