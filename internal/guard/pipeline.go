package guard

import (
	"context"
	"errors"
	"fmt"

	"github.com/github/gh-aw-mcpg/internal/difc"
	"github.com/github/gh-aw-mcpg/internal/logger"
	"github.com/github/gh-aw-mcpg/internal/util"
)

var logPipeline = logger.ForFile()

// PipelineInput holds the shared inputs used across DIFC pipeline phases 0–2, 4, and 6.
// Both the HTTP proxy and the MCP unified server populate this struct and pass it to
// the shared phase helpers, providing their context-specific Phase 3 and Phase 5 logic
// as inline code in their respective callers.
type PipelineInput struct {
	// AgentID identifies the agent in the registry (e.g. "proxy" or an MCP session agent ID).
	AgentID string
	// ToolName is the guard tool name for this request.
	ToolName string
	// Args are the tool arguments; they are stored in context for LabelResponse (Phase 4).
	Args interface{}
	// Guard performs DIFC labeling operations (LabelResource, LabelResponse).
	Guard Guard
	// Evaluator runs coarse-grained and fine-grained DIFC access checks.
	Evaluator *difc.Evaluator
	// AgentRegistry holds per-agent label state.
	AgentRegistry *difc.AgentRegistry
	// Capabilities is the DIFC capability set passed to the guard.
	Capabilities *difc.Capabilities
	// EnforcementMode is the active DIFC enforcement mode.
	EnforcementMode difc.EnforcementMode
	// BackendCaller is used by the guard for metadata enrichment calls.
	BackendCaller BackendCaller
	// SensitiveLogging indicates the resource description may contain a
	// private repository selector (enclave or delegation mode). When true,
	// RunPipelinePrePhases hashes resource.Description before writing it to
	// the shared debug log sink instead of logging it verbatim.
	SensitiveLogging bool
}

// PipelinePreResult holds the outputs from phases 0–2 of the DIFC pipeline.
// Callers use these fields when handling denial responses, Phase 5 filtering, and
// Phase 6 label accumulation.
type PipelinePreResult struct {
	// AgentLabels is the agent's current label set (updated in Phase 6 for propagate mode).
	AgentLabels *difc.AgentLabels
	// Resource is the labeled resource returned by Phase 1.
	Resource *difc.LabeledResource
	// Operation is the operation type determined in Phase 1.
	Operation difc.OperationType
	// CoarseOutcome is the Phase 2 coarse-grained check outcome.
	CoarseOutcome difc.CoarseCheckOutcome
	// EvalResult is the Phase 2 evaluation result (contains Reason for denial messages).
	EvalResult *difc.EvaluationResult
}

// PipelineAccessDenied is returned by RunPipelinePrePhases when Phase 2 denies access.
// Callers inspect EvalResult.Reason to formulate the appropriate denial response
// (HTTP 403 for the proxy, MCP error for the unified server).
type PipelineAccessDenied struct {
	EvalResult  *difc.EvaluationResult
	Resource    *difc.LabeledResource
	AgentLabels *difc.AgentLabels
}

func (e *PipelineAccessDenied) Error() string {
	return fmt.Sprintf("DIFC access denied: %s", e.EvalResult.Reason)
}

// HandlePrePhaseError classifies a RunPipelinePrePhases error.
//
// When err represents a coarse-grained access denial, it returns the canonical
// *PipelineAccessDenied value together with the fully formatted violation error.
// For non-denial errors, it returns (nil, nil).
func HandlePrePhaseError(err error) (*PipelineAccessDenied, error) {
	var denied *PipelineAccessDenied
	if !errors.As(err, &denied) {
		return nil, nil
	}
	return denied, difc.FormatViolationError(
		denied.EvalResult,
		denied.AgentLabels.Secrecy,
		denied.AgentLabels.Integrity,
		denied.Resource,
	)
}

// RunPipelinePrePhases executes phases 0–2 of the DIFC enforcement pipeline:
//
//   - Phase 0: Get or create agent labels from the registry and store tool args in context.
//   - Phase 1: Guard labels the resource (may call backend for metadata enrichment).
//   - Phase 2: Coarse-grained access check; returns *PipelineAccessDenied if access is blocked.
//
// The returned context carries the request state (tool args) required by LabelResponse in Phase 4.
// Callers must use this context for Phase 3 and all subsequent phases.
func RunPipelinePrePhases(ctx context.Context, in PipelineInput) (context.Context, *PipelinePreResult, error) {
	// **Phase 0: Get or create agent labels**
	agentLabels := in.AgentRegistry.GetOrCreate(in.AgentID)
	logPipeline.Printf("[DIFC] Phase 0: agent=%s secrecy=%v integrity=%v",
		util.HashIdentifierForLog(in.AgentID),
		logSafeTags(agentLabels.GetSecrecyTags(), in.SensitiveLogging),
		logSafeTags(agentLabels.GetIntegrityTags(), in.SensitiveLogging))

	// Store tool args in context so LabelResponse (Phase 4) can pass them to the guard.
	ctx = SetRequestStateInContext(ctx, map[string]interface{}{
		"tool_args": in.Args,
	})

	// **Phase 1: Guard labels the resource**
	resource, operation, err := in.Guard.LabelResource(ctx, in.ToolName, in.Args, in.BackendCaller, in.Capabilities)
	if err != nil {
		logPipeline.Printf("[DIFC] Phase 1 failed: tool=%s err=%v", in.ToolName, err)
		return ctx, nil, fmt.Errorf("resource labeling failed: %w", err)
	}
	resourceDescForLog := resource.Description
	if in.SensitiveLogging {
		resourceDescForLog = util.HashForLog(resource.Description, 16, "resource:")
	}
	logPipeline.Printf("[DIFC] Phase 1: resource=%s op=%s secrecy=%v integrity=%v",
		resourceDescForLog, operation,
		logSafeTags(resource.Secrecy.Label.GetTags(), in.SensitiveLogging),
		logSafeTags(resource.Integrity.Label.GetTags(), in.SensitiveLogging))

	// **Phase 2: Coarse-grained access check**
	coarseOutcome, evalResult := difc.EvaluateCoarseAccess(
		in.Evaluator, agentLabels.Secrecy, agentLabels.Integrity, resource, operation)
	switch coarseOutcome {
	case difc.CoarseAllowed:
		logPipeline.Printf("[DIFC] Phase 2: access allowed for agent %s to %s", util.HashIdentifierForLog(in.AgentID), resourceDescForLog)
	case difc.CoarseBypassForRead:
		logPipeline.Printf("[DIFC] Phase 2: coarse check failed for read, proceeding to Phase 3")
	case difc.CoarseDenied:
		logPipeline.Printf("[DIFC] Phase 2: access denied for agent %s to %s: %s",
			util.HashIdentifierForLog(in.AgentID), resourceDescForLog, evalResult.Reason)
		return ctx, nil, &PipelineAccessDenied{
			EvalResult:  evalResult,
			Resource:    resource,
			AgentLabels: agentLabels,
		}
	}

	return ctx, &PipelinePreResult{
		AgentLabels:   agentLabels,
		Resource:      resource,
		Operation:     operation,
		CoarseOutcome: coarseOutcome,
		EvalResult:    evalResult,
	}, nil
}

// RunPipelinePhase4 executes Phase 4 of the DIFC pipeline: guard labels the response.
//
// When ShouldCallLabelResponse returns false for the given operation and enforcement mode,
// the call is skipped and (nil, nil) is returned. Callers should treat nil labeled data as
// "no fine-grained labels available; fall back to coarse-grained result".
//
// The ctx must carry the request state set by RunPipelinePrePhases (tool args for the guard).
func RunPipelinePhase4(ctx context.Context, in PipelineInput, pre *PipelinePreResult, responseData interface{}) (difc.LabeledData, error) {
	if !difc.ShouldCallLabelResponse(pre.Operation, in.EnforcementMode) {
		logPipeline.Printf("[DIFC] Phase 4: skipping LabelResponse for %s operation in %s mode",
			pre.Operation, in.EnforcementMode)
		return nil, nil
	}
	labeledData, err := in.Guard.LabelResponse(ctx, in.ToolName, responseData, in.BackendCaller, in.Capabilities)
	if err != nil {
		logPipeline.Printf("[DIFC] Phase 4 failed: %v", err)
		return nil, fmt.Errorf("response labeling failed: %w", err)
	}
	return labeledData, nil
}

// RunPipelinePhase6 executes Phase 6 of the DIFC pipeline: label accumulation.
//
// When ShouldAccumulateReadLabels returns true for the operation and enforcement mode,
// the agent's label set is updated:
//   - If labeledData is non-nil, labels are accumulated from the response (labeledData.Overall()).
//   - If labeledData is nil, labels are accumulated from the resource determined in Phase 1.
//     This ensures propagate-mode semantics are preserved even when fine-grained labeling
//     was skipped or unavailable.
func RunPipelinePhase6(pre *PipelinePreResult, labeledData difc.LabeledData, enforcementMode difc.EnforcementMode) {
	if !difc.ShouldAccumulateReadLabels(pre.Operation, enforcementMode) {
		return
	}
	if labeledData != nil {
		overall := labeledData.Overall()
		pre.AgentLabels.AccumulateFromRead(overall)
		logPipeline.Printf("[DIFC] Phase 6: accumulated labels from response (agent=%s secrecy=%v integrity=%v)",
			pre.AgentLabels.AgentID, pre.AgentLabels.GetSecrecyTags(), pre.AgentLabels.GetIntegrityTags())
	} else {
		pre.AgentLabels.AccumulateFromRead(pre.Resource)
		logPipeline.Printf("[DIFC] Phase 6: accumulated labels from resource (agent=%s secrecy=%v integrity=%v)",
			pre.AgentLabels.AgentID, pre.AgentLabels.GetSecrecyTags(), pre.AgentLabels.GetIntegrityTags())
	}
}

// logSafeTags renders DIFC label tags for the debug log. Secrecy and integrity
// tags embed the repository selector they protect (for example
// "private:owner/private-repo"), so in enclave and delegation modes each tag is
// replaced with a stable hash. The hash is stable across lines and processes,
// so tag identity and cardinality remain diagnosable without disclosing the
// selector.
func logSafeTags(tags []difc.Tag, sensitive bool) []difc.Tag {
	if !sensitive || len(tags) == 0 {
		return tags
	}
	safe := make([]difc.Tag, len(tags))
	for i, tag := range tags {
		safe[i] = difc.Tag(util.HashForLog(string(tag), 16, "tag:"))
	}
	return safe
}
