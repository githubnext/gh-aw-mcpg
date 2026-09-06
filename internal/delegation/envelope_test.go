package delegation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validEnvelope() *Envelope {
	return &Envelope{
		RunID:               "run-123",
		EnclaveBackend:      "awf-enclave",
		AllowedRepositories: []string{"github/gh-aw", "github/gh-aw-firewall"},
		ToolPolicy:          ToolPolicyGitHubRepositoryReadV1,
		AllowedSchemaHashes: []string{"sha256:abc"},
		MaxIdentityTTL:      5 * time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
	}
}

func TestEnvelopeValidate(t *testing.T) {
	require.NoError(t, validEnvelope().Validate())

	t.Run("missing run id", func(t *testing.T) {
		e := validEnvelope()
		e.RunID = ""
		assert.Error(t, e.Validate())
	})

	t.Run("noncanonical repository rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedRepositories = []string{"GitHub/gh-aw"}
		assert.Error(t, e.Validate())
	})

	t.Run("duplicate repository rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedRepositories = []string{"github/gh-aw", "github/gh-aw"}
		assert.Error(t, e.Validate())
	})

	t.Run("unsupported tool policy rejected", func(t *testing.T) {
		e := validEnvelope()
		e.ToolPolicy = "github-repository-write-v1"
		assert.Error(t, e.Validate())
	})

	t.Run("nil envelope rejected", func(t *testing.T) {
		var e *Envelope
		assert.Error(t, e.Validate())
	})

	t.Run("zero ttl rejected", func(t *testing.T) {
		e := validEnvelope()
		e.MaxIdentityTTL = 0
		assert.Error(t, e.Validate())
	})

	t.Run("owner-only envelope with no repositories is valid", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedRepositories = nil
		e.AllowedOwners = []string{"github"}
		assert.NoError(t, e.Validate())
	})

	t.Run("no repositories and no owners rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedRepositories = nil
		assert.Error(t, e.Validate())
	})

	t.Run("noncanonical owner rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedOwners = []string{"GitHub"}
		assert.Error(t, e.Validate())
	})

	t.Run("duplicate owner rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedOwners = []string{"github", "github"}
		assert.Error(t, e.Validate())
	})

	t.Run("dynamic schema mode with a positive bound is valid", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedSchemaHashes = nil
		e.MaxDynamicSchemaHashes = 1
		assert.NoError(t, e.Validate())
	})

	t.Run("no schema hashes and no dynamic bound rejected", func(t *testing.T) {
		e := validEnvelope()
		e.AllowedSchemaHashes = nil
		assert.Error(t, e.Validate())
	})
}

func TestEnvelopeAllows_OwnerScopedPolicy(t *testing.T) {
	e := validEnvelope()
	e.AllowedRepositories = nil
	e.AllowedOwners = []string{"github"}

	assert.True(t, e.AllowsRepository("github/gh-aw"))
	assert.True(t, e.AllowsRepository("github/any-repo-under-the-owner"))
	assert.False(t, e.AllowsRepository("other-owner/private-repo"), "a sibling owner must not be admitted")
	assert.False(t, e.AllowsRepository("GitHub/gh-aw"), "owner comparison is exact-byte, not case-insensitive")
	assert.False(t, e.AllowsRepository("not-a-canonical-selector"))
}

func TestEnvelopeAllows(t *testing.T) {
	e := validEnvelope()
	assert.True(t, e.AllowsRepository("github/gh-aw"))
	assert.False(t, e.AllowsRepository("github/GH-AW"))
	assert.False(t, e.AllowsRepository("other/other"))
	assert.True(t, e.AllowsSchemaHash("sha256:abc"))
	assert.False(t, e.AllowsSchemaHash("sha256:def"))
}
