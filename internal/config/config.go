package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the FlowGuard configuration
type Config struct {
	Servers map[string]*ServerConfig `toml:"servers"`
}

// ServerConfig represents a single MCP server configuration
type ServerConfig struct {
	Command          string            `toml:"command"`
	Args             []string          `toml:"args"`
	Env              map[string]string `toml:"env"`
	WorkingDirectory string            `toml:"working_directory"`
}

// StdinConfig represents JSON configuration from stdin
type StdinConfig struct {
	MCPServers map[string]*StdinServerConfig `json:"mcpServers"`
	Gateway    *StdinGatewayConfig           `json:"gateway,omitempty"`
}

// StdinServerConfig represents a single server from stdin JSON
type StdinServerConfig struct {
	Type           string            `json:"type"`
	Command        string            `json:"command,omitempty"`
	Args           []string          `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Container      string            `json:"container,omitempty"`
	EntrypointArgs []string          `json:"entrypointArgs,omitempty"`
}

// StdinGatewayConfig represents gateway configuration from stdin JSON
type StdinGatewayConfig struct {
	Port   *int   `json:"port,omitempty"`
	APIKey string `json:"apiKey,omitempty"`
}

// LoadFromFile loads configuration from a TOML file
func LoadFromFile(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to decode TOML: %w", err)
	}
	return &cfg, nil
}

// LoadFromStdin loads configuration from stdin JSON
func LoadFromStdin() (*Config, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdin: %w", err)
	}

	var stdinCfg StdinConfig
	if err := json.Unmarshal(data, &stdinCfg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Log gateway configuration if present (reserved for future use)
	if stdinCfg.Gateway != nil {
		if stdinCfg.Gateway.Port != nil || stdinCfg.Gateway.APIKey != "" {
			log.Println("Gateway configuration present but not yet implemented (reserved for future use)")
		}
	}

	// Convert stdin config to internal format
	cfg := &Config{
		Servers: make(map[string]*ServerConfig),
	}

	for name, server := range stdinCfg.MCPServers {
		// Only support "local" type for now
		if server.Type != "local" {
			log.Printf("Warning: skipping server '%s' with unsupported type '%s'", name, server.Type)
			continue
		}

		// For Docker containers
		if server.Container != "" {
			args := []string{
				"run",
				"--rm",
				"-i",
				// Standard environment variables for better Docker compatibility
				"-e", "NO_COLOR=1",
				"-e", "TERM=dumb",
				"-e", "PYTHONUNBUFFERED=1",
			}

			// Add user-specified environment variables
			// Empty string "" means passthrough from host (just -e KEY)
			// Non-empty string means explicit value (-e KEY=value)
			for k, v := range server.Env {
				args = append(args, "-e")
				if v == "" {
					// Passthrough from host environment
					args = append(args, k)
				} else {
					// Explicit value
					args = append(args, fmt.Sprintf("%s=%s", k, v))
				}
			}

			// Add container name
			args = append(args, server.Container)

			// Add entrypoint args
			args = append(args, server.EntrypointArgs...)

			cfg.Servers[name] = &ServerConfig{
				Command: "docker",
				Args:    args,
				Env:     make(map[string]string),
			}
		} else {
			// Direct command execution
			cfg.Servers[name] = &ServerConfig{
				Command: server.Command,
				Args:    server.Args,
				Env:     server.Env,
			}
		}
	}

	return cfg, nil
}
