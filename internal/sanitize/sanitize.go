// Package sanitize provides utilities for redacting sensitive information from logs.
//
// This package offers two complementary approaches to secret sanitization,
// split across two files for cohesion:
//
//  1. sanitize.go — Pattern-based detection: SanitizeString() and SanitizeJSON()
//     use regex patterns to identify and redact secrets like API keys, tokens, and
//     passwords from arbitrary strings/JSON.
//
//  2. redact.go — Value masking: RedactSecret(), RedactSecretMap(), and RedactURL()
//     mask a known-sensitive value for display, showing only a short safe hint.
//
// Usage Guidelines:
//
//   - Use RedactSecret()/RedactSecretMap() for auth headers and environment variables
//     where you want to preserve a hint of the value for debugging.
//
//   - Use SanitizeString()/SanitizeJSON() for full payload sanitization where secrets
//     may appear in various formats throughout the data.
//
// Example:
//
//	// For auth headers
//	log.Printf("Auth: %s", sanitize.RedactSecret(authHeader)) // "ghp_..." instead of full token
//
//	// For environment variables
//	log.Printf("Env: %v", sanitize.RedactSecretMap(envVars))
//
//	// For JSON payloads
//	sanitized := sanitize.SanitizeJSON(payload) // Replaces detected secrets with [REDACTED]
package sanitize

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// SecretPatterns contains regex patterns for detecting potential secrets
var SecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(token|key|secret|password|auth)[=:]\s*[^\s]{8,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36,}`),                                  // GitHub PATs
	regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),            // GitHub fine-grained PATs
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*`),                    // Bearer tokens
	regexp.MustCompile(`(?i)authorization:\s*[a-zA-Z0-9\-._~+/]+=*`),            // Auth headers
	regexp.MustCompile(`[a-f0-9]{32,}`),                                         // Long hex strings (API keys)
	regexp.MustCompile(`(?i)(apikey|api_key|access_key)[=:]\s*[^\s]{8,}`),       // API keys
	regexp.MustCompile(`(?i)(client_secret|client_id)[=:]\s*[^\s]{8,}`),         // OAuth secrets
	regexp.MustCompile(`[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`), // JWT tokens
	// JSON-specific patterns for field:value pairs
	regexp.MustCompile(`(?i)"(token|password|passwd|pwd|apikey|api_key|api-key|secret|client_secret|api_secret|authorization|auth|key|private_key|public_key|credentials|credential|access_token|refresh_token|bearer_token)"\s*:\s*"[^"]{1,}"`),
}

// separatorRe matches the key/value separator (= or :) with optional trailing spaces.
// Pre-compiled at package level to avoid re-compilation on every SanitizeString call.
var separatorRe = regexp.MustCompile(`[=:]\s*`)

// MarshalAndSanitize marshals value to JSON and sanitizes the result to redact secrets.
// If marshaling fails, it returns a sanitized empty string rather than surfacing a
// logging-only error — callers should use this only in best-effort logging contexts.
func MarshalAndSanitize(value any) string {
	resultJSON, _ := json.Marshal(value)
	return SanitizeString(string(resultJSON))
}

// SanitizeString replaces potential secrets in a string with [REDACTED].
// When private-selector redaction is enabled (enclave and delegation proxy
// profiles), repository selectors, repository API paths, and runtime
// delegation identifiers are additionally replaced with stable hashes.
func SanitizeString(message string) string {
	result := message
	for _, pattern := range SecretPatterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			// Keep the prefix (key name) but redact the value
			if strings.Contains(match, "=") || strings.Contains(match, ":") {
				parts := separatorRe.Split(match, 2)
				if len(parts) == 2 {
					return parts[0] + "=[REDACTED]"
				}
			}
			// For tokens without key=value format, redact entirely
			return "[REDACTED]"
		})
	}
	return RedactPrivateSelectorsIfEnabled(result)
}

// SanitizeJSON sanitizes a JSON payload by applying regex patterns to the entire string
// It takes raw bytes, applies regex sanitization in one pass, and returns sanitized bytes
func SanitizeJSON(payloadBytes []byte) json.RawMessage {
	return SanitizeJSONFromString(SanitizeString(string(payloadBytes)))
}

// SanitizeJSONFromString compacts an already-sanitized JSON string into a
// json.RawMessage. It skips the regex sanitization pass — callers that have
// already called SanitizeString on the payload string can use this to avoid
// running the 10 compiled regex patterns a second time.
func SanitizeJSONFromString(sanitized string) json.RawMessage {
	// Use json.Compact to validate and compact in one pass (avoids a full unmarshal+marshal cycle)
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(sanitized)); err != nil {
		wrapped := map[string]string{
			"_error": "invalid JSON",
			"_raw":   sanitized,
		}
		wrappedBytes, _ := json.Marshal(wrapped)
		return json.RawMessage(wrappedBytes)
	}
	return json.RawMessage(buf.Bytes())
}

// SanitizeArgs returns a sanitized version of command arguments for safe logging.
// It specifically handles Docker-style environment variable arguments (-e VAR=VALUE)
// by truncating ALL values to prevent exposing sensitive data like API tokens.
// This approach prioritizes security over debugging convenience - we truncate all
// environment variable values rather than trying to selectively identify secrets.
// Other arguments are passed through unchanged.
func SanitizeArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	sanitized := make([]string, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Check if this is an environment variable value after a -e flag.
		// Format: -e VAR=VALUE
		if i > 0 && args[i-1] == "-e" {
			if varName, varValue, ok := strings.Cut(arg, "="); ok {
				sanitized[i] = varName + "=" + RedactSecret(varValue)
				continue
			}
		}
		sanitized[i] = arg
	}
	return sanitized
}
