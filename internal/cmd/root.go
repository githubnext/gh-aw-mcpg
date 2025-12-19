package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/githubnext/gh-aw-mcpg/internal/config"
	"github.com/githubnext/gh-aw-mcpg/internal/server"
	"github.com/spf13/cobra"
)

var (
	configFile  string
	configStdin bool
	listenAddr  string
	routedMode  bool
	unifiedMode bool
	envFile     string
)

var rootCmd = &cobra.Command{
	Use:   "flowguard",
	Short: "FlowGuard MCP proxy server",
	Long: `FlowGuard is a proxy server for Model Context Protocol (MCP) servers.
It provides routing, aggregation, and management of multiple MCP backend servers.`,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.toml", "Path to config file")
	rootCmd.Flags().BoolVar(&configStdin, "config-stdin", false, "Read MCP server configuration from stdin (JSON format). When enabled, overrides --config")
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", "127.0.0.1:3000", "HTTP server listen address")
	rootCmd.Flags().BoolVar(&routedMode, "routed", false, "Run in routed mode (each backend at /mcp/<server>)")
	rootCmd.Flags().BoolVar(&unifiedMode, "unified", false, "Run in unified mode (all backends at /mcp)")
	rootCmd.Flags().StringVar(&envFile, "env", "", "Path to .env file to load environment variables")
}

func run(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load .env file if specified
	if envFile != "" {
		if err := loadEnvFile(envFile); err != nil {
			return fmt.Errorf("failed to load .env file: %w", err)
		}
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if configStdin {
		log.Println("Reading configuration from stdin...")
		cfg, err = config.LoadFromStdin()
	} else {
		log.Printf("Reading configuration from %s...", configFile)
		cfg, err = config.LoadFromFile(configFile)
	}

	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log.Printf("Loaded %d MCP server(s)", len(cfg.Servers))

	// Determine mode (default to unified if neither flag is set)
	mode := "unified"
	if routedMode && unifiedMode {
		return fmt.Errorf("cannot specify both --routed and --unified")
	}
	if routedMode {
		mode = "routed"
	}

	// Create unified MCP server (backend for both modes)
	unifiedServer, err := server.NewUnified(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create unified server: %w", err)
	}
	defer unifiedServer.Close()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		unifiedServer.Close()
		os.Exit(0)
	}()

	// Create HTTP server based on mode
	var httpServer *http.Server
	if mode == "routed" {
		log.Printf("Starting FlowGuard in ROUTED mode on %s", listenAddr)
		log.Printf("Routes: /mcp/<server> where <server> is one of: %v", unifiedServer.GetServerIDs())
		httpServer = server.CreateHTTPServerForRoutedMode(listenAddr, unifiedServer)
	} else {
		log.Printf("Starting FlowGuard in UNIFIED mode on %s", listenAddr)
		log.Printf("Endpoint: /mcp")
		httpServer = server.CreateHTTPServerForMCP(listenAddr, unifiedServer)
	}

	// Start HTTP server
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// loadEnvFile reads a .env file and sets environment variables
func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	log.Printf("Loading environment from %s...", path)
	scanner := bufio.NewScanner(file)
	loadedVars := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Expand $VAR references in value
		value = os.ExpandEnv(value)

		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("failed to set %s: %w", key, err)
		}

		// Log loaded variable (hide sensitive values)
		displayValue := value
		if len(value) > 0 {
			displayValue = value[:min(10, len(value))] + "..."
		}
		log.Printf("  Loaded: %s=%s", key, displayValue)
		loadedVars++
	}

	log.Printf("Loaded %d environment variables from %s", loadedVars, path)

	return scanner.Err()
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
