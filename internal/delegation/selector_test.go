package delegation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCanonicalRepositorySelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		want     bool
	}{
		{"simple owner/repo", "github/gh-aw", true},
		{"minimal single-char segments", "a/b", true},
		{"owner with hyphen and repo with dot and underscore", "my-org/my.repo_name", true},
		{"owner starting with digit", "0wner/re-po.name", true},
		{"empty string", "", false},
		{"trailing slash", "github/gh-aw/", false},
		{"leading slash", "/gh-aw", false},
		{"missing repo segment", "github/", false},
		{"uppercase must be rejected, no case folding", "GitHub/gh-aw", false},
		{"trailing whitespace must be rejected, no trimming", "github/gh-aw ", false},
		{"leading whitespace must be rejected, no trimming", " github/gh-aw", false},
		{"embedded control byte", "github/gh-aw\n", false},
		{"URL-encoded slash must not be decoded", "github%2Fgh-aw", false},
		{"repo segment exactly \"..\"", "github/..", false},
		{"repo segment exactly \".\"", "github/.", false},
		{"repo segment containing \"..\"", "github/foo..bar", false},
		{"path traversal attempt", "github/../etc/passwd", false},
		{"non-ASCII byte", "gi™thub/gh-aw", false},
		{"query-injection style suffix", "github/gh-aw?repo=other", false},
		{"NUL-style escape suffix", "github/gh-aw%00", false},
		{"owner cannot start with '-'", "-github/gh-aw", false},
		{"double slash", "github//gh-aw", false},
		{"over-length repo segment", "a/" + strings.Repeat("a", 101), false},
		{"no slash at all", "github-gh-aw", false},
		{"only a slash", "/", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsCanonicalRepositorySelector(tt.selector)
			assert.Equal(t, tt.want, got, "selector %q", tt.selector)
		})
	}
}

func TestDelegatedToolsIsClosedSet(t *testing.T) {
	t.Parallel()

	tools := DelegatedTools()
	require.Len(t, tools, 2, "expected exactly 2 delegated tools, got %v", tools)

	want := []string{"issue_read", "list_issues"}
	a := assert.New(t)
	a.ElementsMatch(want, tools, "DelegatedTools should match the closed allowlist exactly")

	// DelegatedTools returns a sorted, freshly allocated slice each call.
	a.LessOrEqual(tools[0], tools[1], "expected tools to be sorted")
	tools2 := DelegatedTools()
	require.Len(t, tools2, 2, "expected second DelegatedTools call to also return 2 items")
	tools[0] = "mutated"
	a.NotEqual("mutated", tools2[0], "mutating one returned slice must not affect subsequent calls")
}

func TestIsDelegatedTool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tool string
		want bool
	}{
		{"issue_read is delegated", "issue_read", true},
		{"list_issues is delegated", "list_issues", true},
		{"unknown tool is not delegated", "delete_repo", false},
		{"empty tool name is not delegated", "", false},
		{"case-sensitive mismatch is not delegated", "Issue_Read", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsDelegatedTool(tt.tool))
		})
	}
}

func TestToolPolicyGitHubRepositoryReadV1Constant(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "github-repository-read-v1", ToolPolicyGitHubRepositoryReadV1)
}

func TestIsCanonicalOwner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		owner string
		want  bool
	}{
		{"simple owner", "github", true},
		{"owner with hyphen", "my-org", true},
		{"owner starting with digit", "0wner", true},
		{"empty string", "", false},
		{"uppercase must be rejected, no case folding", "GitHub", false},
		{"trailing whitespace must be rejected, no trimming", "github ", false},
		{"owner cannot start with '-'", "-github", false},
		{"contains a slash", "github/gh-aw", false},
		{"non-ASCII byte", "gi™thub", false},
		{"over-length owner", strings.Repeat("a", 40), false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsCanonicalOwner(tt.owner), "owner %q", tt.owner)
		})
	}
}
