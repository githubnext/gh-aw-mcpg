package guard

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/logger"
)

const (
	pipelineRedactionOwner    = "octosecretorg"
	pipelineRedactionRepo     = "privaterepo9"
	pipelineRedactionSelector = pipelineRedactionOwner + "/" + pipelineRedactionRepo
)

// capturePipelineLogs runs f with DEBUG=* and returns what logPipeline wrote to
// stderr. logPipeline resolves DEBUG once at package initialization, so it must
// be rebuilt after the environment is set or the capture would be empty and
// every assertion below would pass vacuously.
func capturePipelineLogs(t *testing.T, f func()) string {
	t.Helper()
	t.Setenv("DEBUG", "*")
	t.Setenv("DEBUG_COLORS", "0")

	previous := logPipeline
	logPipeline = logger.New("guard:pipeline")
	require.True(t, logPipeline.Enabled(), "the capture harness must actually enable debug logging")
	t.Cleanup(func() { logPipeline = previous })

	original := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	var (
		wg  sync.WaitGroup
		buf bytes.Buffer
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()

	func() {
		defer func() {
			os.Stderr = original
			_ = w.Close()
		}()
		f()
	}()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

// newPrivateSelectorPipelineInput builds pipeline input whose resource
// description and DIFC labels all embed a private repository selector, exactly
// as the Rust guard produces them for a delegated request.
func newPrivateSelectorPipelineInput(t *testing.T, sensitive bool) PipelineInput {
	t.Helper()

	resource := difc.NewLabeledResource("issue:" + pipelineRedactionSelector + "#7")
	resource.Secrecy.Label.Add(difc.Tag("private:" + pipelineRedactionSelector))
	resource.Integrity.Label.Add(difc.Tag("repo:" + pipelineRedactionSelector))

	in := newPipelineInput(&pipelineGuard{
		labelResourceResource: resource,
		labelResourceOp:       difc.OperationRead,
	}, difc.OperationRead, difc.EnforcementFilter)
	in.AgentID = "delegation:dlg_handle"
	in.SensitiveLogging = sensitive

	agent := in.AgentRegistry.GetOrCreate(in.AgentID)
	agent.AddSecrecyTags([]difc.Tag{difc.Tag("private:" + pipelineRedactionSelector)})
	agent.AddIntegrityTags([]difc.Tag{difc.Tag("repo:" + pipelineRedactionSelector)})
	return in
}

// TestRunPipelinePrePhases_RedactsPrivateSelectorsWhenSensitive covers the DIFC
// pipeline's own logging. Phase 0 logs the agent's secrecy and integrity tags,
// and Phase 1 logs the resource description plus the resource's tags — every
// one of which embeds the private repository selector for a delegated request.
func TestRunPipelinePrePhases_RedactsPrivateSelectorsWhenSensitive(t *testing.T) {
	in := newPrivateSelectorPipelineInput(t, true)

	logs := capturePipelineLogs(t, func() {
		_, pre, err := RunPipelinePrePhases(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, pre)
	})

	require.Contains(t, logs, "[DIFC] Phase 0", "phase 0 must still be diagnosable")
	require.Contains(t, logs, "[DIFC] Phase 1", "phase 1 must still be diagnosable")
	assert.NotContains(t, logs, pipelineRedactionSelector, "the raw selector must never reach the log sink")
	assert.NotContains(t, logs, pipelineRedactionOwner, "the raw owner must never reach the log sink")
	assert.NotContains(t, logs, pipelineRedactionRepo, "the raw repository must never reach the log sink")
}

// TestRunPipelinePrePhases_KeepsReadableLabelsWhenNotSensitive pins the other
// half of the contract: ordinary, non-delegated deployments keep fully readable
// DIFC diagnostics.
func TestRunPipelinePrePhases_KeepsReadableLabelsWhenNotSensitive(t *testing.T) {
	in := newPrivateSelectorPipelineInput(t, false)

	logs := capturePipelineLogs(t, func() {
		_, pre, err := RunPipelinePrePhases(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, pre)
	})

	assert.Contains(t, logs, pipelineRedactionSelector,
		"non-sensitive deployments must keep readable resource and label diagnostics")
}

// TestLogSafeTagsIsStableAndReversibleOnlyByValue pins that redacted tags stay
// correlatable: identical tags render identically, distinct tags do not
// collide, and cardinality is preserved.
func TestLogSafeTagsIsStableAndReversibleOnlyByValue(t *testing.T) {
	tags := []difc.Tag{
		difc.Tag("private:" + pipelineRedactionSelector),
		difc.Tag("private:" + pipelineRedactionOwner + "/other-repo"),
	}

	safe := logSafeTags(tags, true)
	require.Len(t, safe, len(tags), "tag cardinality must be preserved")
	assert.NotEqual(t, safe[0], safe[1], "distinct tags must render as distinct tokens")
	assert.Equal(t, safe, logSafeTags(tags, true), "tag rendering must be deterministic")

	for i, tag := range safe {
		assert.NotContains(t, string(tag), pipelineRedactionRepo)
		assert.NotEqual(t, tags[i], tag)
	}

	assert.Equal(t, tags, logSafeTags(tags, false), "non-sensitive mode must not rewrite tags")
	assert.Nil(t, logSafeTags(nil, true))
}
