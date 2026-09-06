package githubhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCollaboratorPermissionArgs(t *testing.T) {
	t.Run("returns all fields when present", func(t *testing.T) {
		argsMap := map[string]interface{}{
			"owner":    "myorg",
			"repo":     "myrepo",
			"username": "alice",
		}
		owner, repo, username, err := ParseCollaboratorPermissionArgs(argsMap)
		require.NoError(t, err)
		assert.Equal(t, "myorg", owner)
		assert.Equal(t, "myrepo", repo)
		assert.Equal(t, "alice", username)
	})

	t.Run("error when owner missing", func(t *testing.T) {
		argsMap := map[string]interface{}{
			"repo":     "myrepo",
			"username": "alice",
		}
		owner, repo, username, err := ParseCollaboratorPermissionArgs(argsMap)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing owner/repo/username")
		assert.Empty(t, owner)
		assert.Equal(t, "myrepo", repo)
		assert.Equal(t, "alice", username)
	})

	t.Run("error when repo missing", func(t *testing.T) {
		argsMap := map[string]interface{}{
			"owner":    "myorg",
			"username": "alice",
		}
		owner, repo, username, err := ParseCollaboratorPermissionArgs(argsMap)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing owner/repo/username")
		assert.Equal(t, "myorg", owner)
		assert.Empty(t, repo)
		assert.Equal(t, "alice", username)
	})

	t.Run("error when username missing", func(t *testing.T) {
		argsMap := map[string]interface{}{
			"owner": "myorg",
			"repo":  "myrepo",
		}
		owner, repo, username, err := ParseCollaboratorPermissionArgs(argsMap)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing owner/repo/username")
		assert.Equal(t, "myorg", owner)
		assert.Equal(t, "myrepo", repo)
		assert.Empty(t, username)
	})

	t.Run("returns partial values on error for logging", func(t *testing.T) {
		argsMap := map[string]interface{}{
			"owner": "myorg",
			"repo":  "myrepo",
		}
		owner, repo, username, err := ParseCollaboratorPermissionArgs(argsMap)
		require.Error(t, err)
		assert.Equal(t, "myorg", owner)
		assert.Equal(t, "myrepo", repo)
		assert.Empty(t, username)
	})
}

func TestWrapCollaboratorPermission(t *testing.T) {
	t.Run("logs permission and wraps in MCP format", func(t *testing.T) {
		body := []byte(`{"permission":"admin","user":{"login":"alice"}}`)

		var logged []string
		result := WrapCollaboratorPermission(body, "myorg", "myrepo", "alice", 200, func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}, false)

		// Verify log message includes owner/repo/username context and permission
		require.Len(t, logged, 1)
		assert.Contains(t, logged[0], "myorg/myrepo")
		assert.Contains(t, logged[0], "alice")
		assert.Contains(t, logged[0], `"admin"`)
		assert.Contains(t, logged[0], "HTTP 200")

		// Verify MCP response format
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok, "result should be a map")

		content, ok := resultMap["content"].([]map[string]interface{})
		require.True(t, ok, "content should be array of maps")
		require.Len(t, content, 1)
		assert.Equal(t, "text", content[0]["type"])

		text, ok := content[0]["text"].(string)
		require.True(t, ok, "text should be a string")

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(text), &parsed))
		assert.Equal(t, "admin", parsed["permission"])
	})

	t.Run("logs missing permission field", func(t *testing.T) {
		body := []byte(`{"role":"something"}`)

		var logged []string
		result := WrapCollaboratorPermission(body, "org", "repo", "bob", 200, func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}, false)

		require.Len(t, logged, 1)
		assert.Contains(t, logged[0], "org/repo")
		assert.Contains(t, logged[0], "bob")
		assert.Contains(t, logged[0], "permission field missing")

		// MCP wrap still succeeds
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok)
		content, ok := resultMap["content"].([]map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, string(body), content[0]["text"])
	})

	t.Run("logs JSON parse failure", func(t *testing.T) {
		body := []byte(`not valid json`)

		var logged []string
		result := WrapCollaboratorPermission(body, "org", "repo", "charlie", 200, func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}, false)

		require.Len(t, logged, 1)
		assert.Contains(t, logged[0], "org/repo")
		assert.Contains(t, logged[0], "charlie")
		assert.Contains(t, logged[0], "JSON parse failed")

		// Body is still wrapped even on parse failure
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok)
		content, ok := resultMap["content"].([]map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, string(body), content[0]["text"])
	})

	t.Run("status code is included in log message", func(t *testing.T) {
		body := []byte(`{"permission":"write"}`)

		var logged []string
		WrapCollaboratorPermission(body, "org", "repo", "dave", 201, func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}, false)

		require.Len(t, logged, 1)
		assert.Contains(t, logged[0], "HTTP 201")
	})

	t.Run("sensitive mode hashes owner/repo/username instead of logging them verbatim", func(t *testing.T) {
		body := []byte(`{"permission":"admin"}`)

		var logged []string
		WrapCollaboratorPermission(body, "private-org", "private-repo", "eve", 200, func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		}, true)

		require.Len(t, logged, 1)
		assert.NotContains(t, logged[0], "private-org")
		assert.NotContains(t, logged[0], "private-repo")
		assert.NotContains(t, logged[0], "eve")
		assert.Contains(t, logged[0], "owner:")
		assert.Contains(t, logged[0], "repo:")
		assert.Contains(t, logged[0], "user:")
	})
}

func TestFetchCollaboratorPermissionHelper(t *testing.T) {
	t.Run("successfully fetches and wraps response", func(t *testing.T) {
		var gotPath string
		result, err := FetchCollaboratorPermission(
			context.Background(),
			"myorg",
			"myrepo",
			"alice",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				gotPath = apiPath
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"permission":"admin","user":{"login":"alice"}}`)),
				}, nil
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.NoError(t, err)
		assert.Equal(t, "/repos/myorg/myrepo/collaborators/alice/permission", gotPath)
		assert.NotNil(t, result)
	})

	t.Run("returns fetch errors unchanged", func(t *testing.T) {
		_, err := FetchCollaboratorPermission(
			context.Background(),
			"org",
			"repo",
			"user",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				return nil, fmt.Errorf("REST call failed: boom")
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, "REST call failed: boom")
	})

	t.Run("returns read errors", func(t *testing.T) {
		_, err := FetchCollaboratorPermission(
			context.Background(),
			"org",
			"repo",
			"user",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &failingReadCloser{},
				}, nil
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to read GitHub collaborator API response")
	})

	t.Run("returns status code errors", func(t *testing.T) {
		_, err := FetchCollaboratorPermission(
			context.Background(),
			"org",
			"repo",
			"user",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
				}, nil
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, "GitHub collaborator API returned HTTP 404")
	})

	t.Run("returns error when fetch returns nil response without error", func(t *testing.T) {
		_, err := FetchCollaboratorPermission(
			context.Background(),
			"org",
			"repo",
			"user",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				return nil, nil
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to read GitHub collaborator API response: nil response")
	})

	t.Run("returns error when response body is nil", func(t *testing.T) {
		_, err := FetchCollaboratorPermission(
			context.Background(),
			"org",
			"repo",
			"user",
			func(ctx context.Context, apiPath string) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: nil}, nil
			},
			func(format string, args ...interface{}) {},
			false,
		)
		require.Error(t, err)
		assert.ErrorContains(t, err, "response body is nil")
	})
}

type failingReadCloser struct{}

func (f *failingReadCloser) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read failed")
}

func (f *failingReadCloser) Close() error {
	return nil
}
