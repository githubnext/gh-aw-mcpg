package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("gh-aw-mcpg version %s\n", version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
			printHelp()
			os.Exit(1)
		}
	}

	// Default behavior - print help
	printHelp()
}

func printHelp() {
	fmt.Println("gh-aw-mcpg - Github Agentic Workflows MCP Gateway")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gh-aw-mcpg [command]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  help       Display help information")
	fmt.Println("  version    Display version information")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -h, --help      Display help information")
	fmt.Println("  -v, --version   Display version information")
}
