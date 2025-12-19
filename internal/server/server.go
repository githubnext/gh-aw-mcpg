package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/githubnext/gh-aw-mcpg/internal/launcher"
	"github.com/githubnext/gh-aw-mcpg/internal/mcp"
	"github.com/githubnext/gh-aw-mcpg/internal/sys"
)

// Server represents the FlowGuard HTTP server
type Server struct {
	launcher  *launcher.Launcher
	sysServer *sys.SysServer
	mux       *http.ServeMux
	mode      string // "unified" or "routed"
}

// New creates a new Server
func New(ctx context.Context, l *launcher.Launcher, mode string) *Server {
	s := &Server{
		launcher:  l,
		sysServer: sys.NewSysServer(l.ServerIDs()),
		mux:       http.NewServeMux(),
		mode:      mode,
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	if s.mode == "routed" {
		// Routed mode: /mcp/{server}/{method}
		s.mux.HandleFunc("/mcp/", s.handleRoutedMCP)
	} else {
		// Unified mode: /mcp (single endpoint for all servers)
		s.mux.HandleFunc("/mcp", s.handleUnifiedMCP)
	}

	// Health check
	s.mux.HandleFunc("/health", s.handleHealth)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

func (s *Server) handleUnifiedMCP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read request
	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		s.sendError(w, -32700, "Parse error", nil)
		return
	}
	log.Printf("Unified MCP request - method: %s", req.Method)

	// In unified mode, we need to determine which server to route to
	// For now, default to the first configured server
	// TODO: Implement proper routing logic based on tool name or other criteria
	serverIDs := s.launcher.ServerIDs()
	if len(serverIDs) == 0 {
		s.sendError(w, -32603, "No MCP servers configured", nil)
		return
	}

	serverID := serverIDs[0] // Simple: use first server
	s.proxyToServer(w, r, serverID, &req)
}

func (s *Server) handleRoutedMCP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /mcp/{serverID}
	path := strings.TrimPrefix(r.URL.Path, "/mcp/")
	serverID := strings.Split(path, "/")[0]

	if serverID == "" {
		log.Printf("No server ID in path")
		http.Error(w, "Server ID required in path", http.StatusBadRequest)
		return
	}

	// Read request
	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to decode request body: %v", err)
		s.sendError(w, -32700, "Parse error", nil)
		return
	}
	log.Printf("Routed MCP request - server: %s, method: %s", serverID, req.Method)

	// Handle initialize requests directly (MCP handshake)
	if req.Method == "initialize" {
		s.handleInitialize(w, &req, serverID)
		return
	}

	// Handle notifications/initialized (sent after initialize response)
	if req.Method == "notifications/initialized" {
		log.Printf("Received initialized notification for server: %s", serverID)
		// No response needed for notifications
		w.WriteHeader(http.StatusOK)
		return
	}

	s.proxyToServer(w, r, serverID, &req)
}

func (s *Server) handleInitialize(w http.ResponseWriter, req *mcp.Request, serverID string) {
	log.Printf("Handling initialize request for server: %s", serverID)

	// Return a proper MCP initialize response
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
			"prompts":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "flowguard-" + serverID,
			"version": "1.0.0",
		},
	}

	resultJSON, _ := json.Marshal(result)
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultJSON,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) proxyToServer(w http.ResponseWriter, r *http.Request, serverID string, req *mcp.Request) {
	// Handle built-in sys server
	if serverID == "sys" {
		s.handleSysRequest(w, req)
		return
	}

	// Get or launch connection
	conn, err := launcher.GetOrLaunch(s.launcher, serverID)
	if err != nil {
		log.Printf("Failed to get connection to '%s': %v", serverID, err)
		s.sendError(w, -32603, fmt.Sprintf("Failed to connect to server '%s'", serverID), nil)
		return
	}

	// Forward request based on method
	var resp *mcp.Response

	switch req.Method {
	case "tools/list":
		resp, err = conn.SendRequest("tools/list", nil)
	case "tools/call":
		var params mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(w, -32602, "Invalid params", nil)
			return
		}
		resp, err = conn.SendRequest("tools/call", params)
	default:
		// Forward as-is
		var params interface{}
		if len(req.Params) > 0 {
			json.Unmarshal(req.Params, &params)
		}
		resp, err = conn.SendRequest(req.Method, params)
	}

	if err != nil {
		log.Printf("Error proxying request to '%s': %v", serverID, err)
		s.sendError(w, -32603, "Internal error", nil)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleSysRequest(w http.ResponseWriter, req *mcp.Request) {
	// Handle sys server requests locally
	result, err := s.sysServer.HandleRequest(req.Method, req.Params)
	if err != nil {
		log.Printf("Sys server error: %v", err)
		s.sendError(w, -32603, err.Error(), nil)
		return
	}

	// Marshal result
	resultJSON, err := json.Marshal(result)
	if err != nil {
		s.sendError(w, -32603, "Failed to marshal result", nil)
		return
	}

	// Create response
	resp := &mcp.Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultJSON,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) sendError(w http.ResponseWriter, code int, message string, data interface{}) {
	resp := &mcp.Response{
		JSONRPC: "2.0",
		Error: &mcp.ResponseError{
			Code:    code,
			Message: message,
		},
	}

	if data != nil {
		dataBytes, _ := json.Marshal(data)
		resp.Error.Data = dataBytes
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // MCP errors still return 200
	json.NewEncoder(w).Encode(resp)
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the HTTP server
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("Starting FlowGuard HTTP server on %s (mode: %s)", addr, s.mode)
	return http.ListenAndServe(addr, s)
}
