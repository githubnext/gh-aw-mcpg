package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLoadFromStdin_ValidJSON(t *testing.T) {
	jsonConfig := `{
		"mcpServers": {
			"test": {
				"type": "local",
				"container": "test/container:latest",
				"entrypointArgs": ["arg1", "arg2"],
				"env": {
					"TEST_VAR": "value",
					"PASSTHROUGH_VAR": ""
				}
			}
		}
	}`

	// Mock stdin
	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		w.Write([]byte(jsonConfig))
		w.Close()
	}()

	cfg, err := LoadFromStdin()
	os.Stdin = oldStdin

	if err != nil {
		t.Fatalf("LoadFromStdin() failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("LoadFromStdin() returned nil config")
	}

	if len(cfg.Servers) != 1 {
		t.Errorf("Expected 1 server, got %d", len(cfg.Servers))
	}

	server, ok := cfg.Servers["test"]
	if !ok {
		t.Fatal("Server 'test' not found in config")
	}

	if server.Command != "docker" {
		t.Errorf("Expected command 'docker', got '%s'", server.Command)
	}

	// Check that standard Docker env vars are included
	hasNoColor := false
	hasTerm := false
	hasPythonUnbuffered := false
	hasTestVar := false
	hasPassthrough := false

	for i := 0; i < len(server.Args); i++ {
		arg := server.Args[i]
		if arg == "-e" && i+1 < len(server.Args) {
			nextArg := server.Args[i+1]
			if nextArg == "NO_COLOR=1" {
				hasNoColor = true
			} else if nextArg == "TERM=dumb" {
				hasTerm = true
			} else if nextArg == "PYTHONUNBUFFERED=1" {
				hasPythonUnbuffered = true
			} else if nextArg == "TEST_VAR=value" {
				hasTestVar = true
			} else if nextArg == "PASSTHROUGH_VAR" {
				hasPassthrough = true
			}
		}
	}

	if !hasNoColor {
		t.Error("Standard env var NO_COLOR=1 not found")
	}
	if !hasTerm {
		t.Error("Standard env var TERM=dumb not found")
	}
	if !hasPythonUnbuffered {
		t.Error("Standard env var PYTHONUNBUFFERED=1 not found")
	}
	if !hasTestVar {
		t.Error("Custom env var TEST_VAR=value not found")
	}
	if !hasPassthrough {
		t.Error("Passthrough env var PASSTHROUGH_VAR not found")
	}

	// Check that container name is in args
	if !contains(server.Args, "test/container:latest") {
		t.Error("Container name not found in args")
	}

	// Check that entrypoint args are included
	if !contains(server.Args, "arg1") || !contains(server.Args, "arg2") {
		t.Error("Entrypoint args not found")
	}
}

func TestLoadFromStdin_WithGateway(t *testing.T) {
	port := 8080
	jsonConfig := `{
		"mcpServers": {
			"test": {
				"type": "local",
				"container": "test/container:latest"
			}
		},
		"gateway": {
			"port": 8080,
			"apiKey": "test-key"
		}
	}`

	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		w.Write([]byte(jsonConfig))
		w.Close()
	}()

	_, err := LoadFromStdin()
	os.Stdin = oldStdin

	if err != nil {
		t.Fatalf("LoadFromStdin() failed: %v", err)
	}

	// Gateway should be parsed but not affect server config
	var stdinCfg StdinConfig
	json.Unmarshal([]byte(jsonConfig), &stdinCfg)

	if stdinCfg.Gateway == nil {
		t.Error("Gateway not parsed")
	}
	if stdinCfg.Gateway.Port == nil || *stdinCfg.Gateway.Port != port {
		t.Error("Gateway port not correct")
	}
	if stdinCfg.Gateway.APIKey != "test-key" {
		t.Error("Gateway API key not correct")
	}
}

func TestLoadFromStdin_UnsupportedType(t *testing.T) {
	jsonConfig := `{
		"mcpServers": {
			"unsupported": {
				"type": "remote",
				"container": "test/container:latest"
			},
			"supported": {
				"type": "local",
				"container": "test/container:latest"
			}
		}
	}`

	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		w.Write([]byte(jsonConfig))
		w.Close()
	}()

	cfg, err := LoadFromStdin()
	os.Stdin = oldStdin

	if err != nil {
		t.Fatalf("LoadFromStdin() failed: %v", err)
	}

	// Only 'local' type should be loaded
	if len(cfg.Servers) != 1 {
		t.Errorf("Expected 1 server (local type only), got %d", len(cfg.Servers))
	}

	if _, ok := cfg.Servers["unsupported"]; ok {
		t.Error("Unsupported server type was loaded")
	}

	if _, ok := cfg.Servers["supported"]; !ok {
		t.Error("Supported server type was not loaded")
	}
}

func TestLoadFromStdin_DirectCommand(t *testing.T) {
	jsonConfig := `{
		"mcpServers": {
			"direct": {
				"type": "local",
				"command": "node",
				"args": ["index.js"],
				"env": {
					"NODE_ENV": "production"
				}
			}
		}
	}`

	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		w.Write([]byte(jsonConfig))
		w.Close()
	}()

	cfg, err := LoadFromStdin()
	os.Stdin = oldStdin

	if err != nil {
		t.Fatalf("LoadFromStdin() failed: %v", err)
	}

	server, ok := cfg.Servers["direct"]
	if !ok {
		t.Fatal("Server 'direct' not found")
	}

	if server.Command != "node" {
		t.Errorf("Expected command 'node', got '%s'", server.Command)
	}

	if !contains(server.Args, "index.js") {
		t.Error("Args not preserved for direct command")
	}

	if server.Env["NODE_ENV"] != "production" {
		t.Error("Env vars not preserved for direct command")
	}
}

func TestLoadFromStdin_InvalidJSON(t *testing.T) {
	jsonConfig := `{invalid json}`

	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	go func() {
		w.Write([]byte(jsonConfig))
		w.Close()
	}()

	_, err := LoadFromStdin()
	os.Stdin = oldStdin

	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}

	if !strings.Contains(err.Error(), "parse JSON") {
		t.Errorf("Expected 'parse JSON' error, got: %v", err)
	}
}

// Helper function to check if slice contains item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
