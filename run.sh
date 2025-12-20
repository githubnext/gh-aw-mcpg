#!/bin/bash

# Set DOCKER_API_VERSION based on architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    export DOCKER_API_VERSION=1.43
else
    export DOCKER_API_VERSION=1.44
fi

# Default values
HOST="${HOST:- 0.0.0.0}"
PORT="${PORT:-8000}"
CONFIG="${CONFIG}"
ENV_FILE="${ENV_FILE:-.env}"
MODE="${MODE:---routed}"

# Build the command
CMD="./flowguard-go"
FLAGS="$MODE --listen ${HOST}:${PORT}"

# Only add --env flag if ENV_FILE is set and the file exists
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    FLAGS="$FLAGS --env $ENV_FILE"
    echo "Using environment file: $ENV_FILE"
elif [ -n "$ENV_FILE" ]; then
    echo "Warning: ENV_FILE specified ($ENV_FILE) but file not found, skipping..."
fi

if [ -n "$CONFIG" ]; then
    if [ -f "$CONFIG" ]; then
        FLAGS="$FLAGS --config $CONFIG"
        echo "Using config file: $CONFIG"
    else
        echo "Warning: CONFIG specified ($CONFIG) but file not found, using default config..."
        FLAGS="$FLAGS --config-stdin"
        CONFIG_JSON=$(cat <<EOF
{
    "mcpServers": {
        "github": {
            "type": "local",
            "container": "ghcr.io/github/github-mcp-server:latest",
            "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": ""
            }
        },
        "fetch": {
            "type": "local",
            "container": "mcp/fetch"
        },
        "memory": {
            "type": "local",
            "container": "mcp/memory"
        }
    }
}
EOF
)
    fi
else
    echo "No config file specified, using default config..."
    FLAGS="$FLAGS --config-stdin"
    CONFIG_JSON=$(cat <<EOF
{
    "mcpServers": {
        "github": {
            "type": "local",
            "container": "ghcr.io/github/github-mcp-server:latest",
            "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": ""
            }
        },
        "fetch": {
            "type": "local",
            "container": "mcp/fetch"
        },
        "memory": {
            "type": "local",
            "container": "mcp/memory"
        }
    }
}
EOF
)
fi

echo "Starting FlowGuard Go server on port $PORT..."
echo "Command: $CMD $FLAGS"

# Execute the command
echo "$CONFIG_JSON" | $CMD $FLAGS