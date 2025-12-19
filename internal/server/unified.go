package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/githubnext/gh-aw-mcpg/internal/config"
	"github.com/githubnext/gh-aw-mcpg/internal/launcher"
	"github.com/githubnext/gh-aw-mcpg/internal/sys"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session represents a FlowGuard session
type Session struct {
	Token     string
	SessionID string
}

// ContextKey for session ID (exported so transport can use it)
type ContextKey string

// SessionIDContextKey is used to store MCP session ID in context
const SessionIDContextKey ContextKey = "flowguard-session-id"

// ToolInfo stores metadata about a registered tool
type ToolInfo struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	BackendID   string // Which backend this tool belongs to
	Handler     func(context.Context, *sdk.CallToolRequest, interface{}) (*sdk.CallToolResult, interface{}, error)
}

// UnifiedServer implements a unified MCP server that aggregates multiple backend servers
type UnifiedServer struct {
	launcher  *launcher.Launcher
	sysServer *sys.SysServer
	ctx       context.Context
	server    *sdk.Server
	sessions  map[string]*Session // mcp-session-id -> Session
	sessionMu sync.RWMutex
	tools     map[string]*ToolInfo // prefixed tool name -> tool info
	toolsMu   sync.RWMutex
}

// NewUnified creates a new unified MCP server
func NewUnified(ctx context.Context, cfg *config.Config) (*UnifiedServer, error) {
	l := launcher.New(ctx, cfg)

	us := &UnifiedServer{
		launcher:  l,
		sysServer: sys.NewSysServer(l.ServerIDs()),
		ctx:       ctx,
		sessions:  make(map[string]*Session),
		tools:     make(map[string]*ToolInfo),
	}

	// Create MCP server
	server := sdk.NewServer(&sdk.Implementation{
		Name:    "flowguard-unified",
		Version: "1.0.0",
	}, nil)

	us.server = server

	// Register aggregated tools from all backends
	if err := us.registerAllTools(); err != nil {
		return nil, fmt.Errorf("failed to register tools: %w", err)
	}

	return us, nil
}

// registerAllTools fetches and registers tools from all backend servers
func (us *UnifiedServer) registerAllTools() error {
	log.Println("Registering tools from all backends...")

	// Register sys tools first
	log.Println("Registering sys tools...")
	if err := us.registerSysTools(); err != nil {
		log.Printf("Warning: failed to register sys tools: %v", err)
	}

	// Register tools from each backend server
	for _, serverID := range us.launcher.ServerIDs() {
		if err := us.registerToolsFromBackend(serverID); err != nil {
			log.Printf("Warning: failed to register tools from %s: %v", serverID, err)
			// Continue with other backends
		}
	}

	return nil
}

// registerToolsFromBackend registers tools from a specific backend with <server>___<tool> naming
func (us *UnifiedServer) registerToolsFromBackend(serverID string) error {
	log.Printf("Registering tools from backend: %s", serverID)

	// Get connection to backend
	conn, err := launcher.GetOrLaunch(us.launcher, serverID)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// List tools from backend
	result, err := conn.SendRequest("tools/list", nil)
	if err != nil {
		return fmt.Errorf("failed to list tools: %w", err)
	}

	// Parse the result
	var listResult struct {
		Tools []struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			InputSchema map[string]interface{} `json:"inputSchema"`
		} `json:"tools"`
	}

	if err := json.Unmarshal(result.Result, &listResult); err != nil {
		return fmt.Errorf("failed to parse tools: %w", err)
	}

	// Register each tool with prefixed name
	toolNames := []string{}
	for _, tool := range listResult.Tools {
		prefixedName := fmt.Sprintf("%s___%s", serverID, tool.Name)
		toolDesc := fmt.Sprintf("[%s] %s", serverID, tool.Description)
		toolNames = append(toolNames, prefixedName)

		// Store tool info for routed mode
		us.toolsMu.Lock()
		us.tools[prefixedName] = &ToolInfo{
			Name:        prefixedName,
			Description: toolDesc,
			InputSchema: tool.InputSchema,
			BackendID:   serverID,
		}
		us.toolsMu.Unlock()

		// Create a closure to capture serverID and toolName
		serverIDCopy := serverID
		toolNameCopy := tool.Name

		// Create the handler function
		handler := func(ctx context.Context, req *sdk.CallToolRequest, args interface{}) (*sdk.CallToolResult, interface{}, error) {
			// Check session is initialized
			if err := us.requireSession(ctx); err != nil {
				return &sdk.CallToolResult{IsError: true}, nil, err
			}
			return us.callBackendTool(ctx, serverIDCopy, toolNameCopy, args)
		}

		// Store handler for routed mode to reuse
		us.toolsMu.Lock()
		us.tools[prefixedName].Handler = handler
		us.toolsMu.Unlock()

		// Register the tool with the SDK
		sdk.AddTool(us.server, &sdk.Tool{
			Name:        prefixedName,
			Description: toolDesc,
			InputSchema: tool.InputSchema,
		}, handler)

		log.Printf("Registered tool: %s", prefixedName)
	}

	log.Printf("Registered %d tools from %s: %v", len(listResult.Tools), serverID, toolNames)
	return nil
}

// registerSysTools registers built-in sys tools
func (us *UnifiedServer) registerSysTools() error {
	// Create sys_init handler
	sysInitHandler := func(ctx context.Context, req *sdk.CallToolRequest, args interface{}) (*sdk.CallToolResult, interface{}, error) {
		// Extract token from args
		token := ""
		if argsMap, ok := args.(map[string]interface{}); ok {
			if t, ok := argsMap["token"].(string); ok {
				token = t
			}
		}

		// TODO: Security check on token will be implemented later

		// Get session ID from context
		sessionID := us.getSessionID(ctx)
		if sessionID == "" {
			return &sdk.CallToolResult{IsError: true}, nil, fmt.Errorf("no session ID provided")
		}

		// Create session
		us.sessionMu.Lock()
		us.sessions[sessionID] = &Session{
			Token:     token,
			SessionID: sessionID,
		}
		us.sessionMu.Unlock()

		log.Printf("Initialized session: %s", sessionID)

		// Call sys_init
		params, _ := json.Marshal(map[string]interface{}{
			"name":      "sys_init",
			"arguments": map[string]interface{}{},
		})
		result, err := us.sysServer.HandleRequest("tools/call", json.RawMessage(params))
		if err != nil {
			return &sdk.CallToolResult{IsError: true}, nil, err
		}
		return nil, result, nil
	}

	// Store sys_init tool info
	us.toolsMu.Lock()
	us.tools["sys___init"] = &ToolInfo{
		Name:        "sys___init",
		Description: "Initialize the FlowGuard system and get available MCP servers",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "Authentication token for session initialization (can be empty for first call)",
				},
			},
		},
		BackendID: "sys",
		Handler:   sysInitHandler,
	}
	us.toolsMu.Unlock()

	// Register with SDK
	sdk.AddTool(us.server, &sdk.Tool{
		Name:        "sys___init",
		Description: "Initialize the FlowGuard system and get available MCP servers",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "Authentication token for session initialization (can be empty for first call)",
				},
			},
		},
	}, sysInitHandler)

	// Create sys_list_servers handler
	sysListHandler := func(ctx context.Context, req *sdk.CallToolRequest, args interface{}) (*sdk.CallToolResult, interface{}, error) {
		// Check session is initialized
		if err := us.requireSession(ctx); err != nil {
			return &sdk.CallToolResult{IsError: true}, nil, err
		}

		params, _ := json.Marshal(map[string]interface{}{
			"name":      "sys_list_servers",
			"arguments": map[string]interface{}{},
		})
		result, err := us.sysServer.HandleRequest("tools/call", json.RawMessage(params))
		if err != nil {
			return &sdk.CallToolResult{IsError: true}, nil, err
		}
		return nil, result, nil
	}

	// Store sys_list_servers tool info
	us.toolsMu.Lock()
	us.tools["sys___list_servers"] = &ToolInfo{
		Name:        "sys___list_servers",
		Description: "List all configured MCP backend servers",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		BackendID: "sys",
		Handler:   sysListHandler,
	}
	us.toolsMu.Unlock()

	// Register with SDK
	sdk.AddTool(us.server, &sdk.Tool{
		Name:        "sys___list_servers",
		Description: "List all configured MCP backend servers",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}, sysListHandler)

	log.Println("Registered 2 sys tools")
	return nil
}

// callBackendTool calls a tool on a backend server
func (us *UnifiedServer) callBackendTool(ctx context.Context, serverID, toolName string, args interface{}) (*sdk.CallToolResult, interface{}, error) {
	// Note: Session validation happens at the tool registration level via closures
	// The closure captures the request and validates before calling this method
	log.Printf("Calling tool on %s: %s", serverID, toolName)

	// Get connection to backend
	conn, err := launcher.GetOrLaunch(us.launcher, serverID)
	if err != nil {
		return &sdk.CallToolResult{IsError: true}, nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Call the tool
	response, err := conn.SendRequest("tools/call", map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	})
	if err != nil {
		return &sdk.CallToolResult{IsError: true}, nil, err
	}

	// Parse the result
	var result interface{}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return &sdk.CallToolResult{IsError: true}, nil, fmt.Errorf("failed to parse result: %w", err)
	}

	return nil, result, nil
}

// Run starts the unified MCP server on the specified transport
func (us *UnifiedServer) Run(transport sdk.Transport) error {
	log.Println("Starting unified MCP server...")
	return us.server.Run(us.ctx, transport)
}

// getSessionID extracts the MCP session ID from the context
func (us *UnifiedServer) getSessionID(ctx context.Context) string {
	if sessionID, ok := ctx.Value(SessionIDContextKey).(string); ok && sessionID != "" {
		log.Printf("Extracted session ID from context: %s", sessionID)
		return sessionID
	}
	// No session ID in context - this happens before the SDK assigns one
	// For now, use "default" as a placeholder for single-client scenarios
	// In production multi-agent scenarios, the SDK will provide session IDs after initialize
	log.Printf("No session ID in context, using 'default' (this is normal before SDK session is established)")
	return "default"
}

// requireSession checks that a session has been initialized for this request
func (us *UnifiedServer) requireSession(ctx context.Context) error {
	sessionID := us.getSessionID(ctx)
	log.Printf("Checking session for ID: %s", sessionID)

	us.sessionMu.RLock()
	session := us.sessions[sessionID]
	us.sessionMu.RUnlock()

	if session == nil {
		log.Printf("Session not found for ID: %s. Available sessions: %v", sessionID, us.getSessionKeys())
		return fmt.Errorf("sys___init must be called before any other tool calls")
	}

	log.Printf("Session validated for ID: %s", sessionID)
	return nil
}

// getSessionKeys returns a list of active session IDs for debugging
func (us *UnifiedServer) getSessionKeys() []string {
	us.sessionMu.RLock()
	defer us.sessionMu.RUnlock()

	keys := make([]string, 0, len(us.sessions))
	for k := range us.sessions {
		keys = append(keys, k)
	}
	return keys
}

// GetServerIDs returns the list of backend server IDs
func (us *UnifiedServer) GetServerIDs() []string {
	return us.launcher.ServerIDs()
}

// GetToolsForBackend returns tools for a specific backend with prefix stripped
func (us *UnifiedServer) GetToolsForBackend(backendID string) []ToolInfo {
	us.toolsMu.RLock()
	defer us.toolsMu.RUnlock()

	prefix := backendID + "___"
	filtered := make([]ToolInfo, 0)

	for _, tool := range us.tools {
		if tool.BackendID == backendID {
			// Create a copy with the prefix stripped from the name
			filteredTool := *tool
			filteredTool.Name = tool.Name[len(prefix):] // Strip prefix
			filtered = append(filtered, filteredTool)
		}
	}

	return filtered
}

// GetToolHandler returns the handler for a specific backend tool
// This allows routed mode to reuse the unified server's tool handlers
func (us *UnifiedServer) GetToolHandler(backendID string, toolName string) func(context.Context, *sdk.CallToolRequest, interface{}) (*sdk.CallToolResult, interface{}, error) {
	us.toolsMu.RLock()
	defer us.toolsMu.RUnlock()

	prefixedName := backendID + "___" + toolName
	if toolInfo, ok := us.tools[prefixedName]; ok {
		return toolInfo.Handler
	}
	return nil
}

// Close cleans up resources
func (us *UnifiedServer) Close() error {
	us.launcher.Close()
	return nil
}
