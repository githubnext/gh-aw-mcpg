package server

import (
	"context"
	"testing"

	"github.com/githubnext/gh-aw-mcpg/internal/config"
)

func TestUnifiedServer_GetServerIDs(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{
			"github": {Command: "docker", Args: []string{}},
			"fetch":  {Command: "docker", Args: []string{}},
		},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	serverIDs := us.GetServerIDs()
	if len(serverIDs) != 2 {
		t.Errorf("Expected 2 server IDs, got %d", len(serverIDs))
	}

	expectedIDs := map[string]bool{"github": true, "fetch": true}
	for _, id := range serverIDs {
		if !expectedIDs[id] {
			t.Errorf("Unexpected server ID: %s", id)
		}
	}
}

func TestUnifiedServer_SessionManagement(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	// Test session creation
	sessionID := "test-session-123"
	token := "test-token"

	us.sessionMu.Lock()
	us.sessions[sessionID] = &Session{
		Token:     token,
		SessionID: sessionID,
	}
	us.sessionMu.Unlock()

	// Test session retrieval
	us.sessionMu.RLock()
	session, exists := us.sessions[sessionID]
	us.sessionMu.RUnlock()

	if !exists {
		t.Error("Session not found after creation")
	}

	if session.Token != token {
		t.Errorf("Expected token '%s', got '%s'", token, session.Token)
	}

	if session.SessionID != sessionID {
		t.Errorf("Expected session ID '%s', got '%s'", sessionID, session.SessionID)
	}
}

func TestUnifiedServer_GetSessionKeys(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	// Add multiple sessions
	sessions := []string{"session-1", "session-2", "session-3"}
	for _, sid := range sessions {
		us.sessionMu.Lock()
		us.sessions[sid] = &Session{SessionID: sid, Token: "token"}
		us.sessionMu.Unlock()
	}

	keys := us.getSessionKeys()
	if len(keys) != len(sessions) {
		t.Errorf("Expected %d session keys, got %d", len(sessions), len(keys))
	}

	keyMap := make(map[string]bool)
	for _, key := range keys {
		keyMap[key] = true
	}

	for _, expected := range sessions {
		if !keyMap[expected] {
			t.Errorf("Session key '%s' not found", expected)
		}
	}
}

func TestUnifiedServer_GetToolsForBackend(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	// Manually add some tool info
	us.toolsMu.Lock()
	us.tools["github___issue_read"] = &ToolInfo{
		Name:        "github___issue_read",
		Description: "Read an issue",
		BackendID:   "github",
	}
	us.tools["github___repo_list"] = &ToolInfo{
		Name:        "github___repo_list",
		Description: "List repositories",
		BackendID:   "github",
	}
	us.tools["fetch___get"] = &ToolInfo{
		Name:        "fetch___get",
		Description: "Fetch a URL",
		BackendID:   "fetch",
	}
	us.toolsMu.Unlock()

	// Test filtering for github backend
	githubTools := us.GetToolsForBackend("github")
	if len(githubTools) != 2 {
		t.Errorf("Expected 2 GitHub tools, got %d", len(githubTools))
	}

	for _, tool := range githubTools {
		if tool.BackendID != "github" {
			t.Errorf("Expected BackendID 'github', got '%s'", tool.BackendID)
		}
		// Check that prefix is stripped
		if tool.Name == "github___issue_read" || tool.Name == "github___repo_list" {
			t.Errorf("Tool name '%s' still has prefix", tool.Name)
		}
		if tool.Name != "issue_read" && tool.Name != "repo_list" {
			t.Errorf("Unexpected tool name after prefix strip: '%s'", tool.Name)
		}
	}

	// Test filtering for fetch backend
	fetchTools := us.GetToolsForBackend("fetch")
	if len(fetchTools) != 1 {
		t.Errorf("Expected 1 fetch tool, got %d", len(fetchTools))
	}

	if fetchTools[0].Name != "get" {
		t.Errorf("Expected tool name 'get', got '%s'", fetchTools[0].Name)
	}

	// Test filtering for non-existent backend
	noTools := us.GetToolsForBackend("nonexistent")
	if len(noTools) != 0 {
		t.Errorf("Expected 0 tools for nonexistent backend, got %d", len(noTools))
	}
}

func TestGetSessionID_FromContext(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	// Test with session ID in context
	sessionID := "test-bearer-token-123"
	ctxWithSession := context.WithValue(ctx, SessionIDContextKey, sessionID)

	extractedID := us.getSessionID(ctxWithSession)
	if extractedID != sessionID {
		t.Errorf("Expected session ID '%s', got '%s'", sessionID, extractedID)
	}

	// Test without session ID in context
	extractedID = us.getSessionID(ctx)
	if extractedID != "default" {
		t.Errorf("Expected default session ID, got '%s'", extractedID)
	}
}

func TestRequireSession(t *testing.T) {
	cfg := &config.Config{
		Servers: map[string]*config.ServerConfig{},
	}

	ctx := context.Background()
	us, err := NewUnified(ctx, cfg)
	if err != nil {
		t.Fatalf("NewUnified() failed: %v", err)
	}
	defer us.Close()

	// Create a session
	sessionID := "valid-session"
	us.sessionMu.Lock()
	us.sessions[sessionID] = &Session{SessionID: sessionID, Token: "token"}
	us.sessionMu.Unlock()

	// Test with valid session
	ctxWithSession := context.WithValue(ctx, SessionIDContextKey, sessionID)
	err = us.requireSession(ctxWithSession)
	if err != nil {
		t.Errorf("requireSession() failed for valid session: %v", err)
	}

	// Test with invalid session
	ctxWithInvalidSession := context.WithValue(ctx, SessionIDContextKey, "invalid-session")
	err = us.requireSession(ctxWithInvalidSession)
	if err == nil {
		t.Error("requireSession() should fail for invalid session")
	}
}
