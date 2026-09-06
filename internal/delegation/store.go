package delegation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	handleRandomBytes = 16
	bearerRandomBytes = 32
)

// Store atomically creates/confirms and revokes delegated identities for one
// compiler-installed Envelope. It is safe for concurrent use: every mutating
// operation is serialized so that concurrent create/confirm/revoke calls for
// the same idempotency key are atomic and generation-safe.
type Store struct {
	mu sync.Mutex

	// persistMu serializes SaveState calls so concurrent persistence
	// snapshots are always written in the same order their in-memory
	// snapshot was taken, ensuring a later (or equal) snapshot can never be
	// overwritten on disk by an earlier one that happened to finish its
	// write last.
	persistMu sync.Mutex

	envelope   *Envelope
	generation uint64

	byHandle     map[string]*Identity
	byBearer     map[[sha256.Size]byte]*Identity
	byInvocation map[string]*Identity            // invocationScopeKey -> identity
	byLabel      map[string]map[string]*Identity // labelKey -> handle -> identity

	// dynamicSchemaHashes bounds runtime-admitted schema hashes when the
	// envelope's AllowedSchemaHashes is empty (dynamic enclave mode). It is
	// unused, and must stay empty, whenever AllowedSchemaHashes is
	// non-empty.
	dynamicSchemaHashes map[string]struct{}

	// recoveryIncomplete is set when the controller could not fully
	// reconstruct labelled live delegations after a restart. A failed
	// recovery always yields a store with zero identities indexed, so while
	// the flag is set every data-plane authorization is refused as well as
	// every new dynamic admission. Only revocations still succeed.
	recoveryIncomplete bool
}

// NewStore creates an empty Store bound to envelope. generation is the
// compiler-supplied policy generation for this envelope installation; it is
// stamped onto every identity minted from this Store so a later envelope
// replacement can be distinguished from stale identities.
func NewStore(envelope *Envelope, generation uint64) (*Store, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	envelopeCopy := *envelope
	envelopeCopy.AllowedRepositories = slices.Clone(envelope.AllowedRepositories)
	envelopeCopy.AllowedOwners = slices.Clone(envelope.AllowedOwners)
	envelopeCopy.AllowedSchemaHashes = slices.Clone(envelope.AllowedSchemaHashes)
	return &Store{
		envelope:            &envelopeCopy,
		generation:          generation,
		byHandle:            make(map[string]*Identity),
		byBearer:            make(map[[sha256.Size]byte]*Identity),
		byInvocation:        make(map[string]*Identity),
		byLabel:             make(map[string]map[string]*Identity),
		dynamicSchemaHashes: make(map[string]struct{}),
	}, nil
}

// IsRecoveryIncomplete reports whether restart reconstruction left this Store
// unable to vouch for prior state. When true the Store holds zero identities
// and both new dynamic admissions and data-plane authorizations are refused
// until MarkReconciled clears the flag.
func (s *Store) IsRecoveryIncomplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryIncomplete
}

// MarkReconciled clears the recovery-incomplete flag once an operator or
// automated process has confirmed outstanding state is safe to resume from.
func (s *Store) MarkReconciled() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoveryIncomplete = false
}

func generateOpaqueToken(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate delegation token: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// validateAgainstEnvelope enforces that req is a strict subset of the
// compiler-installed envelope. Every rejection reason here is a policy
// violation, never a lookup miss, so callers must fail closed on error.
func (s *Store) validateAgainstEnvelope(req CreateOrConfirmRequest, now time.Time) error {
	if now.After(s.envelope.ExpiresAt) {
		return fmt.Errorf("envelope expired")
	}
	if req.RunID == "" || req.RunID != s.envelope.RunID {
		return fmt.Errorf("run id outside envelope")
	}
	if req.EnclaveBackend == "" || req.EnclaveBackend != s.envelope.EnclaveBackend {
		return fmt.Errorf("enclave backend outside envelope")
	}
	if req.EnclaveEntryID == "" {
		return fmt.Errorf("enclave entry id is required")
	}
	if req.InvocationID == "" {
		return fmt.Errorf("invocation id is required")
	}
	if req.IdempotencyKey == "" {
		return fmt.Errorf("idempotency key is required")
	}
	if !IsCanonicalRepositorySelector(req.Repository) || !s.envelope.AllowsRepository(req.Repository) {
		return fmt.Errorf("repository outside envelope")
	}
	if req.ToolPolicy != s.envelope.ToolPolicy {
		return fmt.Errorf("tool policy outside envelope")
	}
	if req.SchemaHash == "" {
		return fmt.Errorf("schema hash is required")
	}
	if len(s.envelope.AllowedSchemaHashes) > 0 && !s.envelope.AllowsSchemaHash(req.SchemaHash) {
		return fmt.Errorf("schema hash outside envelope")
	}
	if len(s.envelope.AllowedSchemaHashes) == 0 && s.envelope.MaxDynamicSchemaHashes <= 0 {
		// Defensive invariant check: Envelope.Validate (enforced by NewStore)
		// already rejects this combination, so this should be unreachable in
		// practice. Kept as a fail-closed guard against a future envelope
		// constructed without going through Validate.
		return fmt.Errorf("envelope does not admit any schema hash")
	}
	if req.RequestedTTL <= 0 || req.RequestedTTL > s.envelope.MaxIdentityTTL {
		return fmt.Errorf("requested ttl outside envelope")
	}
	if !req.InvocationExpiresAt.IsZero() && !now.Before(req.InvocationExpiresAt) {
		return fmt.Errorf("invocation deadline has elapsed")
	}
	return nil
}

// CreateOrConfirm atomically creates a new delegated identity, or confirms an
// existing one for the same invocation scope. A repeated call for the same
// (run, enclave entry, invocation) tuple returns the exact same binding,
// expiry, admitted default-branch SHA, opaque handle, and executor bearer,
// regardless of whether the caller supplies the same idempotency key: one
// active or terminal identity binding is enforced per invocation even when a
// caller varies the idempotency key across retries. A request whose binding
// differs from the stored identity is terminal: the stored identity is
// revoked and an error is returned.
func (s *Store) CreateOrConfirm(req CreateOrConfirmRequest) (*IdentityResult, error) {
	return s.createOrConfirmAt(req, time.Now())
}

func (s *Store) createOrConfirmAt(req CreateOrConfirmRequest, now time.Time) (*IdentityResult, error) {
	if err := s.validateAgainstEnvelope(req, now); err != nil {
		emitAudit(newAuditEvent("create_or_confirm", req, "denied", "envelope-subset-violation", s.generation))
		return nil, fmt.Errorf("delegation request denied: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupExpiredLocked(now)

	key := invocationScopeKey(req.RunID, req.EnclaveEntryID, req.InvocationID)
	if existing, ok := s.byInvocation[key]; ok {
		if existing.bindingEquals(req) {
			if existing.Revoked {
				return nil, fmt.Errorf("delegation request denied: invocation has a terminal outcome")
			}
			emitAudit(newAuditEvent("confirm", req, "confirmed", "idempotent-replay", s.generation))
			return existing.toResult(), nil
		}
		// Terminal mismatch: revoke any partial state bound to this
		// invocation so it cannot be confused with the newly requested
		// binding, even when the caller supplied a different idempotency
		// key than the one that originally created it.
		s.revokeLocked(existing)
		emitAudit(newAuditEventWithHandle("create_or_confirm", req, "mismatch", "invocation-binding-mismatch", existing.Handle, s.generation))
		return nil, fmt.Errorf("delegation request denied: invocation bound to a different identity")
	}

	if s.recoveryIncomplete {
		emitAudit(newAuditEvent("create_or_confirm", req, "denied", "recovery-incomplete", s.generation))
		return nil, fmt.Errorf("delegation request denied: restart recovery incomplete")
	}

	if !s.admitSchemaHashLocked(req.SchemaHash) {
		emitAudit(newAuditEvent("create_or_confirm", req, "denied", "dynamic-schema-hash-bound-exceeded", s.generation))
		return nil, fmt.Errorf("delegation request denied: dynamic schema hash bound exceeded")
	}

	handle, err := generateOpaqueToken("dlg_", handleRandomBytes)
	if err != nil {
		return nil, err
	}
	bearer, err := generateOpaqueToken("dlgbearer_", bearerRandomBytes)
	if err != nil {
		return nil, err
	}

	identity := &Identity{
		Handle:                   handle,
		ExecutorBearer:           bearer,
		RunID:                    req.RunID,
		EnclaveBackend:           req.EnclaveBackend,
		EnclaveEntryID:           req.EnclaveEntryID,
		InvocationID:             req.InvocationID,
		Repository:               req.Repository,
		ToolPolicy:               req.ToolPolicy,
		SchemaHash:               req.SchemaHash,
		AdmittedDefaultBranchSHA: req.AdmittedDefaultBranchSHA,
		ExpiresAt:                identityExpiry(now, req.RequestedTTL, s.envelope.ExpiresAt, req.InvocationExpiresAt),
		InvocationExpiresAt:      req.InvocationExpiresAt,
		PolicyGeneration:         s.generation,
		IdempotencyKey:           req.IdempotencyKey,
		CreatedAt:                now,
	}
	s.indexLocked(identity)

	emitAudit(newAuditEvent("create_or_confirm", req, "admitted", "created", s.generation))
	return identity.toResult(), nil
}

// admitSchemaHashLocked reports whether hash is admissible under the
// envelope's schema policy, and if the envelope uses bounded dynamic
// admission (AllowedSchemaHashes is empty), records hash as admitted so a
// later call can reuse it without consuming another slot of the bound. It
// must be called with s.mu held.
func (s *Store) admitSchemaHashLocked(hash string) bool {
	if s.envelope.AllowsSchemaHash(hash) {
		return true
	}
	if len(s.envelope.AllowedSchemaHashes) > 0 {
		return false
	}
	if _, ok := s.dynamicSchemaHashes[hash]; ok {
		return true
	}
	if len(s.dynamicSchemaHashes) >= s.envelope.MaxDynamicSchemaHashes {
		return false
	}
	s.dynamicSchemaHashes[hash] = struct{}{}
	return true
}

func (s *Store) indexLocked(identity *Identity) {
	key := invocationScopeKey(identity.RunID, identity.EnclaveEntryID, identity.InvocationID)
	s.byHandle[identity.Handle] = identity
	s.byBearer[sha256.Sum256([]byte(identity.ExecutorBearer))] = identity
	s.byInvocation[key] = identity
	label := labelKey(identity.RunID, identity.EnclaveEntryID)
	if s.byLabel[label] == nil {
		s.byLabel[label] = make(map[string]*Identity)
	}
	s.byLabel[label][identity.Handle] = identity
}

func identityExpiry(now time.Time, requestedTTL time.Duration, deadlines ...time.Time) time.Time {
	expiry := now.Add(requestedTTL)
	for _, deadline := range deadlines {
		if !deadline.IsZero() && deadline.Before(expiry) {
			expiry = deadline
		}
	}
	return expiry
}

func (s *Store) revokeLocked(identity *Identity) {
	identity.Revoked = true
	delete(s.byHandle, identity.Handle)
	delete(s.byBearer, sha256.Sum256([]byte(identity.ExecutorBearer)))
	key := invocationScopeKey(identity.RunID, identity.EnclaveEntryID, identity.InvocationID)
	// Retain a terminal tombstone for the envelope lifetime. Reusing this
	// invocation must never mint a renewed identity, regardless of the
	// idempotency key supplied.
	s.byInvocation[key] = identity
	label := labelKey(identity.RunID, identity.EnclaveEntryID)
	if labelled, ok := s.byLabel[label]; ok {
		delete(labelled, identity.Handle)
		if len(labelled) == 0 {
			delete(s.byLabel, label)
		}
	}
}

// cleanupExpiredLocked removes identities whose expiry has passed. It must be
// called with s.mu held.
func (s *Store) cleanupExpiredLocked(now time.Time) {
	for _, identity := range s.byHandle {
		if !now.Before(identity.ExpiresAt) {
			expired := *identity
			s.revokeLocked(identity)
			emitAudit(newIdentityAuditEvent("expire", &expired, "expired", "ttl-elapsed"))
		}
	}
}

// Revoke idempotently revokes the identity bound to handle. Revoking an
// unknown or already-revoked handle is not an error.
func (s *Store) Revoke(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.byHandle[handle]
	if !ok {
		emitAudit(newHandleAuditEvent("revoke", handle, "revoked", "already-absent"))
		return nil
	}
	s.revokeLocked(identity)
	emitAudit(newIdentityAuditEvent("revoke", identity, "revoked", "explicit"))
	return nil
}

// RevokeByLabels idempotently revokes every identity bound to (runID,
// enclaveEntryID) and returns how many identities were revoked. It is used
// both for explicit label-scoped revocation and for shutdown/reconciliation
// cleanup.
func (s *Store) RevokeByLabels(runID, enclaveEntryID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	label := labelKey(runID, enclaveEntryID)
	labelled, ok := s.byLabel[label]
	if !ok {
		return 0
	}
	handles := make([]string, 0, len(labelled))
	for handle := range labelled {
		handles = append(handles, handle)
	}
	for _, handle := range handles {
		if identity, ok := s.byHandle[handle]; ok {
			s.revokeLocked(identity)
		}
	}
	emitAudit(newLabelAuditEvent("revoke_by_labels", runID, enclaveEntryID, "revoked", fmt.Sprintf("count=%d", len(handles))))
	return len(handles)
}

// Authorize enforces that executorBearer is a live identity bound to exactly the
// given run, enclave backend, repository, and tool. It rejects replayed,
// expired, revoked, wrong-repository, wrong-tool, and wrong-run identities;
// none of those can establish or continue a session.
func (s *Store) Authorize(executorBearer, runID, enclaveBackend, repository, tool string) error {
	_, err := s.authorize(executorBearer, repository, tool, func(identity *Identity) bool {
		return identity.RunID == runID && identity.EnclaveBackend == enclaveBackend
	})
	return err
}

// AuthorizeExecutor authorizes an executor bearer against the repository and
// tool derived by the data-plane route. The run and backend are read from the
// authenticated identity rather than supplied by the executor. On success it
// returns the identity's opaque handle so the caller can bind the request to
// a delegation-specific isolation context (for example a DIFC identity)
// rather than falling back to the shared proxy identity.
func (s *Store) AuthorizeExecutor(executorBearer, repository, tool string) (string, error) {
	identity, err := s.authorize(executorBearer, repository, tool, func(*Identity) bool { return true })
	if err != nil {
		return "", err
	}
	return identity.Handle, nil
}

func (s *Store) authorize(executorBearer, repository, tool string, bindingMatches func(*Identity) bool) (*Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.cleanupExpiredLocked(now)

	// A store whose recovery failed carries no identities, so no bearer can
	// match below. Refusing up front makes that guarantee explicit and
	// independent of the loader: if a future change ever reconstructs some
	// state before detecting corruption, the data plane still fails closed.
	if s.recoveryIncomplete {
		return nil, fmt.Errorf("delegation state recovery is incomplete")
	}
	if !now.Before(s.envelope.ExpiresAt) {
		return nil, fmt.Errorf("delegation envelope has expired")
	}
	if bearer, ok := strings.CutPrefix(executorBearer, "Bearer "); ok {
		executorBearer = bearer
	}
	identity, ok := s.byBearer[sha256.Sum256([]byte(executorBearer))]
	if !ok {
		return nil, fmt.Errorf("unknown or revoked delegated identity")
	}
	if !bindingMatches(identity) {
		return nil, fmt.Errorf("delegated identity is not bound to this run or enclave backend")
	}
	if identity.Repository != repository {
		return nil, fmt.Errorf("delegated identity is not bound to this repository")
	}
	if !IsDelegatedTool(tool) {
		return nil, fmt.Errorf("tool is outside the delegated policy")
	}
	return identity, nil
}

// StoreStatus is a redacted snapshot of controller health AWF uses to decide
// whether it may resume delegated admissions. It never discloses a
// repository, credential, or header.
type StoreStatus struct {
	// RecoveryIncomplete reports whether restart reconstruction left this
	// Store unable to vouch for prior state. New dynamic admissions are
	// refused while this is true.
	RecoveryIncomplete bool `json:"recovery_incomplete"`
	// Generation is the compiler-supplied policy generation bound to this
	// Store.
	Generation uint64 `json:"generation"`
	// LiveIdentityCount is the number of currently live (non-expired,
	// non-revoked) identities.
	LiveIdentityCount int `json:"live_identity_count"`
}

// Status returns a redacted snapshot of controller health for the status
// control-plane operation.
func (s *Store) Status() StoreStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	return StoreStatus{
		RecoveryIncomplete: s.recoveryIncomplete,
		Generation:         s.generation,
		LiveIdentityCount:  len(s.byHandle),
	}
}

// LabelHandles returns the opaque handles of every live identity bound to
// (runID, enclaveEntryID), sorted for deterministic output, so AWF can
// enumerate labelled state during reconciliation without any repository,
// credential, or header ever being disclosed.
func (s *Store) LabelHandles(runID, enclaveEntryID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	label := labelKey(runID, enclaveEntryID)
	labelled := s.byLabel[label]
	handles := make([]string, 0, len(labelled))
	for handle := range labelled {
		handles = append(handles, handle)
	}
	slices.Sort(handles)
	return handles
}

// Snapshot returns a defensive copy of every currently live (non-expired,
// non-revoked) identity, keyed by handle. It is used for state persistence
// ahead of restart recovery.
func (s *Store) Snapshot() map[string]Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	out := make(map[string]Identity, len(s.byHandle))
	for handle, identity := range s.byHandle {
		out[handle] = *identity
	}
	return out
}
