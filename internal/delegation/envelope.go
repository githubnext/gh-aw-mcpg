package delegation

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Envelope is the compiler-installed, compiler-bounded policy envelope
// bootstrapped into the controller at gateway startup. Every delegated
// identity must be a strict subset of this envelope; the controller rejects
// any request for a server, tool, repository, credential, backend URL, or
// guard policy outside it. The compiler is not a runtime service: once
// installed the envelope is immutable for the lifetime of the process.
type Envelope struct {
	// RunID is the workflow run this envelope, and every identity minted
	// from it, is bound to.
	RunID string `json:"run_id"`
	// EnclaveBackend is the single AWF enclave backend identities may be
	// bound to.
	EnclaveBackend string `json:"enclave_backend"`
	// AllowedRepositories is the closed set of canonical owner/repo
	// selectors the compiler admitted for this run. Selectors are compared
	// as exact ASCII byte sequences; no normalization is performed.
	AllowedRepositories []string `json:"allowed_repositories"`
	// AllowedOwners is the closed set of canonical repository owners the
	// compiler admitted for this run's dynamic enclaves. When set, AWF may
	// select any exact repository under an allowed owner at invocation
	// time without the compiler enumerating every repository in advance.
	// A repository is admitted if it is a member of AllowedRepositories or
	// its owner segment is a member of AllowedOwners; one identity remains
	// bound to exactly one repository either way. Owners are compared as
	// exact ASCII byte sequences; no normalization is performed.
	AllowedOwners []string `json:"allowed_owners,omitempty"`
	// ToolPolicy is the single delegated tool policy this envelope allows.
	// Only ToolPolicyGitHubRepositoryReadV1 is currently supported.
	ToolPolicy string `json:"tool_policy"`
	// AllowedSchemaHashes is the closed set of finite response schema
	// hashes the compiler approved for this run. It may be left empty to
	// use MaxDynamicSchemaHashes' bounded runtime admission instead.
	AllowedSchemaHashes []string `json:"allowed_schema_hashes"`
	// MaxDynamicSchemaHashes bounds how many distinct invocation-supplied
	// schema hashes may be admitted at runtime when AllowedSchemaHashes is
	// empty, so a dynamic enclave can be authorized against a bounded
	// finite-schema policy without every hash being enumerated at compile
	// time. It has no effect when AllowedSchemaHashes is non-empty: in
	// that case only the exact compiled hashes are ever admitted.
	MaxDynamicSchemaHashes int `json:"max_dynamic_schema_hashes,omitempty"`
	// MaxIdentityTTL bounds how long any single delegated identity may
	// live, and therefore how long an executor bearer remains valid.
	MaxIdentityTTL time.Duration `json:"max_identity_ttl"`
	// ExpiresAt is the envelope's own absolute expiry, no later than the
	// workflow job lifetime. No identity may be created once the envelope
	// itself has expired.
	ExpiresAt time.Time `json:"expires_at"`
}

// Validate checks the envelope's own invariants. It does not check any
// per-request binding; use Envelope.Admits for that.
func (e *Envelope) Validate() error {
	if e == nil {
		return fmt.Errorf("delegation envelope is required")
	}
	if e.RunID == "" {
		return fmt.Errorf("envelope run id is required")
	}
	if e.EnclaveBackend == "" {
		return fmt.Errorf("envelope enclave backend is required")
	}
	if len(e.AllowedRepositories) == 0 && len(e.AllowedOwners) == 0 {
		return fmt.Errorf("envelope must admit at least one repository or owner")
	}
	seen := make(map[string]struct{}, len(e.AllowedRepositories))
	for _, repo := range e.AllowedRepositories {
		if !IsCanonicalRepositorySelector(repo) {
			return fmt.Errorf("envelope repository %q is not a canonical selector", repo)
		}
		if _, dup := seen[repo]; dup {
			return fmt.Errorf("envelope must not contain duplicate repository %q", repo)
		}
		seen[repo] = struct{}{}
	}
	seenOwners := make(map[string]struct{}, len(e.AllowedOwners))
	for _, owner := range e.AllowedOwners {
		if !IsCanonicalOwner(owner) {
			return fmt.Errorf("envelope owner %q is not a canonical selector", owner)
		}
		if _, dup := seenOwners[owner]; dup {
			return fmt.Errorf("envelope must not contain duplicate owner %q", owner)
		}
		seenOwners[owner] = struct{}{}
	}
	if e.ToolPolicy != ToolPolicyGitHubRepositoryReadV1 {
		return fmt.Errorf("unsupported envelope tool policy %q", e.ToolPolicy)
	}
	if len(e.AllowedSchemaHashes) == 0 && e.MaxDynamicSchemaHashes <= 0 {
		return fmt.Errorf("envelope must admit at least one schema hash or a positive max dynamic schema hash bound")
	}
	if e.MaxIdentityTTL <= 0 {
		return fmt.Errorf("envelope max identity ttl must be positive")
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Errorf("envelope expiry is required")
	}
	return nil
}

// AllowsRepository reports whether repo is admitted by this envelope: either
// as an exact-byte member of AllowedRepositories, or by its owner segment
// being an exact-byte member of AllowedOwners. repo must already be a
// canonical selector; a non-canonical selector is never admitted through the
// owner path even if its literal prefix would otherwise match.
func (e *Envelope) AllowsRepository(repo string) bool {
	if slices.Contains(e.AllowedRepositories, repo) {
		return true
	}
	if len(e.AllowedOwners) == 0 || !IsCanonicalRepositorySelector(repo) {
		return false
	}
	owner, _, ok := strings.Cut(repo, "/")
	if !ok {
		return false
	}
	return slices.Contains(e.AllowedOwners, owner)
}

// AllowsSchemaHash reports whether schemaHash is an exact-byte member of the
// envelope's admitted schema hash set.
func (e *Envelope) AllowsSchemaHash(schemaHash string) bool {
	return slices.Contains(e.AllowedSchemaHashes, schemaHash)
}
