package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPTransport wraps the SDK's HTTP transport
type HTTPTransport struct {
	Addr string
}

// Start implements sdk.Transport interface
func (t *HTTPTransport) Start(ctx context.Context) error {
	// The SDK will handle the actual HTTP server setup
	// We just need to provide the address
	log.Printf("HTTP transport ready on %s", t.Addr)
	return nil
}

// Send implements sdk.Transport interface
func (t *HTTPTransport) Send(msg interface{}) error {
	// Messages are sent via HTTP responses, handled by SDK
	return nil
}

// Recv implements sdk.Transport interface
func (t *HTTPTransport) Recv() (interface{}, error) {
	// Messages are received via HTTP requests, handled by SDK
	return nil, nil
}

// Close implements sdk.Transport interface
func (t *HTTPTransport) Close() error {
	return nil
}

// loggingResponseWriter wraps http.ResponseWriter to capture response body
type loggingResponseWriter struct {
	http.ResponseWriter
	body []byte
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

// CreateHTTPServerForMCP creates an HTTP server that handles MCP over SSE
func CreateHTTPServerForMCP(addr string, unifiedServer *UnifiedServer) *http.Server {
	mux := http.NewServeMux()

	// OAuth discovery endpoint - return 404 since we don't use OAuth
	mux.HandleFunc("/mcp/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s - OAuth discovery (not supported)", r.RemoteAddr, r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	// Create StreamableHTTP handler for MCP protocol (supports POST requests)
	// This is what Codex uses with transport = "streamablehttp"
	streamableHandler := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		// With SSE, this callback fires ONCE per HTTP connection establishment
		// All subsequent JSON-RPC messages come over the same persistent connection
		// We use the Bearer token from Authorization header as the session ID
		// This groups all routes from the same agent (same token) into one session

		// Extract Bearer token from Authorization header
		authHeader := r.Header.Get("Authorization")
		var sessionID string

		if strings.HasPrefix(authHeader, "Bearer ") {
			sessionID = strings.TrimPrefix(authHeader, "Bearer ")
			sessionID = strings.TrimSpace(sessionID)
		}

		// Reject requests without valid Bearer token
		if sessionID == "" {
			log.Printf("[%s] %s %s - REJECTED: No Bearer token", r.RemoteAddr, r.Method, r.URL.Path)
			// Return nil to reject the connection
			// The SDK will handle sending an appropriate error response
			return nil
		}

		log.Printf("=== NEW SSE CONNECTION ===")
		log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		log.Printf("Bearer Token (Session ID): %s", sessionID)

		log.Printf("DEBUG: About to check request body, Method=%s, Body!=nil: %v", r.Method, r.Body != nil)

		// Log request body for debugging (typically the 'initialize' request)
		if r.Method == "POST" && r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil && len(bodyBytes) > 0 {
				log.Printf("Request body: %s", string(bodyBytes))
				// Restore body
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// Store session ID in request context
		// This context will be passed to all tool handlers for this connection
		ctx := context.WithValue(r.Context(), SessionIDContextKey, sessionID)
		*r = *r.WithContext(ctx)
		log.Printf("✓ Injected session ID into context")
		log.Printf("==========================\n")

		return unifiedServer.server
	}, &sdk.StreamableHTTPOptions{
		Stateless: false, // Support stateful sessions
	})

	// Mount streamableHandler directly at /mcp endpoint (logging is done in the callback above)
	mux.Handle("/mcp/", streamableHandler)
	mux.Handle("/mcp", streamableHandler)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}
