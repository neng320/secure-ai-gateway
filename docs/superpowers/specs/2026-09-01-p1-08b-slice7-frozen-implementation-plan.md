# P1-08B Slice 7 Frozen Implementation Plan

```text
STATUS=FROZEN_APPROVED
TASK_ID=P1-08B
SLICE=7
SOURCE_BASE_HEAD=73fd066c1b44f1bb1d1b7c311359eea62f2efe84
AUTHORITATIVE_BRANCH=task/p1-08b-audit-logging
AUTHORITATIVE_ENV=Ubuntu-SecureGateway / native Linux ext4 / Go + CGO + SQLite
PLAN_SOURCES=
SLICE_7_IMPLEMENTATION_PLAN_V2
SLICE_7_IMPLEMENTATION_PLAN_V2_FINAL_DELTA
PRECEDENCE=
FINAL_DELTA overrides conflicting V2 text
IMPLEMENTATION_STARTED=false
PR_AUTHORIZED=false
MERGE_AUTHORIZED=false
TAG_AUTHORIZED=false
```

This is the sole canonical plan for Luna's P1-08B Slice 7 implementation. Follow
the tasks and gates in order. The implementation delivery stops after a normal push
of the same task branch.

## 1. Goal, guarantees, and limits

Slice 7 closes provider-migration and request-scrub audit gaps, durable config
replacement, credential entropy failures, reset-password test/operations debt,
listener test debt, viewer gates, and the final P1-08 documentation.

SQLite and a config file cannot share a transaction. `VACUUM` cannot run inside
the request-log UPDATE transaction. The implementation therefore uses explicit
commit points and resumable maintenance operations. It must not claim cross-store
or power-loss atomicity.

Guaranteed:

- SQLite business mutation and its audit append share one SQLite transaction where
  the mutation is SQLite-backed.
- Returned config-write failures enter exact-byte compensation when rename may have
  occurred.
- Offline multi-commit work has durable STARTED evidence and a correlated,
  success-only completion event.
- Pending work resumes with the same operation UUID.

Not guaranteed:

- one transaction across config, SQLite, and provider recovery backup;
- one transaction across request-log UPDATE, `VACUUM`, and completion audit;
- code-level proof that another gateway process is stopped;
- protection from a root/database owner replacing the complete database.

The audit canonical encoding/hash protocol and existing P1-05/06/07 semantics stay
unchanged.

## 2. Two-phase maintenance audit

Fixed actions:

```text
PROVIDER_SECRET_MIGRATION_STARTED
PROVIDER_SECRET_MIGRATION
REQUEST_LOG_SCRUB_STARTED
REQUEST_LOG_SCRUB
```

Actions without `_STARTED` are success-only.

Trusted fields:

```text
ActorType=cli
Provider ActorID=migrate-provider-secrets
Scrub ActorID=scrub-request-log-content
TargetType=maintenance-operation
TargetID=<server-generated UUID>
Reason=""
```

The audit maintenance module alone generates TargetID. It never accepts the UUID
from CLI, stdin, config, HTTP, forms, headers, or other user input. Resume uses
only a UUID recovered from verified audit history.

No secret, hash, envelope, Master Key, Authorization value, cookie, session,
request body, error body, config dump, path, backup content, or arbitrary payload
may enter these events.

## 3. Maintenance serialization invariant

```text
Acquire authoritative serialization
→ acquire SQLite writer serialization
→ pending lookup
→ validate cardinality
→ resume/new decision
→ server UUID if new
→ STARTED append
→ commit
```

The unlocked sequence `pending lookup → gap → later STARTED append` is forbidden.
Multiple pending operations, orphan/duplicate SUCCESS, invalid UUID, or
actor/action/target mismatch are integrity failures.

Provider migration holds the config mutation lock for the complete invocation.
Within it, a real SQLite transaction obtains the audit-chain writer lock before
pending lookup. Lookup, decision, UUID generation, and STARTED append stay in that
transaction.

Request scrub uses one pinned offline SQLite connection and establishes its
offline-exclusive ownership before the audit prerequisite. `audit.MigrateIntegrity`
and current-integrity verification use that same authoritative offline DB and
connection path. `BEGIN EXCLUSIVE` then occurs before pending lookup. Lookup,
decision, STARTED, and logical clearing stay in that exclusive transaction.

The maintenance module exposes the minimum interface needed to begin/resume and
complete a fixed maintenance kind inside a caller-owned active transaction. It
must verify the active transaction and acquire writer serialization before reading
pending state.

## 4. Provider-secret migration

### 4.1 Preserved behavior

Keep the existing encrypted-secret classifier, invalid-envelope fail-closed rules,
legacy semantic preservation, PREPARE/VERIFY/FINALIZE state machine, sensitive
recovery snapshot, and safe mixed-state reruns.

### 4.2 Final flow

```text
Acquire config mutation lock
→ read config
→ validate DB/base schema

→ audit.MigrateIntegrity
→ verify current audit integrity

→ SQLite writer transaction:
     acquire audit-chain writer lock
     → pending lookup
     → validate pending cardinality
     → reuse pending operation UUID
       OR generate new server UUID
     → append PROVIDER_SECRET_MIGRATION_STARTED
     → COMMIT

→ create recovery backup

→ existing provider schema/PREPARE/VERIFY

→ final SQLite transaction:
     clear client legacy secrets
     → append PROVIDER_SECRET_MIGRATION success with the same TargetID
     → durable config FINALIZE
     → config file fsync
     → containing-directory fsync
     → SQLite COMMIT

→ success
```

### 4.3 Audit prerequisite and backup

- Legacy audit schema is upgraded only by `audit.MigrateIntegrity`: deterministic
  backfill, chain state, exact triggers, and verification in one transaction.
- Current-valid audit is verified without history rewrite.
- Current-corrupt event/state/index/trigger/link/hash/head fails closed.
- Current corruption permits no STARTED, provider backup, or provider mutation.
- STARTED failure rolls back its transaction and permits no provider backup or
  provider mutation. Audit schema may already have been legally upgraded.
- Backup is created only after STARTED commits.
- DB backup therefore includes current audit schema, verified chain, triggers/state,
  and PROVIDER_SECRET_MIGRATION_STARTED.
- Config backup remains provider-pre-mutation original bytes.
- “Before mutation” means before provider schema/data/config mutation, not before
  audit migration or STARTED.
- Backup failure leaves one pending STARTED and zero provider mutation.
- Rerun reuses that UUID and retries backup without another STARTED.
- Never auto-replace the complete live SQLite file from the recovery backup.

### 4.4 Final-commit failure gate

If config FINALIZE is durable but final SQLite COMMIT fails:

```text
config compensated to safe PREPARE state
SUCCESS audit not committed
client DB FINALIZE not committed
STARTED remains
operation remains resumable
migration success is not reported
```

Restore also uses durable replacement. Restore failure or post-rename restore
directory-sync failure returns a stable rollback/recovery-required error and does
not claim durable recovery.

Crash interpretation:

- before STARTED commit: no provider operation;
- after STARTED and before backup: pending, provider mutation zero;
- after PREPARE: pending and resumable;
- after durable config FINALIZE: final SQLite transaction atomically decides
  client FINALIZE plus SUCCESS; otherwise STARTED remains pending;
- after final SQLite commit: operation complete.

### 4.5 Provider tests

Add focused tests for:

- legacy audit migration before STARTED;
- current corruption: no STARTED/backup/provider mutation;
- STARTED failure: no backup/provider mutation;
- backup failure: exactly one pending STARTED;
- rerun reuses TargetID;
- successful exactly-one STARTED/SUCCESS pair;
- completion failure leaves safe PREPARE and pending STARTED;
- durable config FINALIZE plus SQLite COMMIT failure compensates to PREPARE;
- global-only, client-only, combined, mixed, and already-encrypted behavior;
- event and raw-DB canaries for key/envelope/Master-Key/path privacy.

## 5. Request-log scrub

### 5.1 Preserved physical model

```text
offline exclusive ownership
→ WAL checkpoint where applicable
→ secure_delete best effort
→ logical UPDATE
→ WAL→DELETE where applicable
→ VACUUM
→ physical and logical verification
```

No plaintext recovery backup is created.

### 5.2 Final flow

```text
pinned offline SQLite connection
→ configure/obtain offline exclusive ownership
→ audit.MigrateIntegrity using the same authoritative offline DB/connection path
→ verify current audit integrity
→ BEGIN EXCLUSIVE

same transaction:
  pending lookup
  → validate cardinality
  → resume UUID OR generate server UUID
  → append REQUEST_LOG_SCRUB_STARTED
  → clear request_body/error_message
  → COMMIT

→ WAL→DELETE where applicable
→ VACUUM
→ physical verification
→ logical verification

→ new exclusive transaction on the same pinned connection
  → append REQUEST_LOG_SCRUB success with the same TargetID
  → COMMIT

→ close
```

SUCCESS appears only after VACUUM plus physical and logical verification. UPDATE,
VACUUM, and SUCCESS are not one transaction.

The audit prerequisite is part of the same pinned offline-exclusive ownership
model; it must not mutate audit schema through an unlocked DB path and acquire
scrub exclusivity only afterward. Legacy or fresh audit schema may be upgraded to
the current P1-08B audit schema before STARTED. Current-valid audit state is
verified and continues. Current-corrupt event history, state head, or trigger
definitions fail closed without repair: STARTED count remains zero, request-log
UPDATE count remains zero, VACUUM count remains zero, and SUCCESS count remains
zero. Audit migration or verification failure leaves request-log content
logically and byte-for-byte unchanged.

If the current GORM/SQLite interfaces cannot preserve the same pinned
offline-exclusive ownership across `audit.MigrateIntegrity`, integrity
verification, the logical `BEGIN EXCLUSIVE` transaction, COMMIT, VACUUM, and the
completion transaction, implementation stops with `ARCHITECTURE_CONFLICT`; it
must not weaken the P1-04 offline exclusivity gate.

### 5.3 Resume semantics

`dirty rows = 0` plus exactly one pending STARTED is not a new no-op. It may mean
logical clearing committed while physical scrub/completion did not.

```text
reuse same operation UUID
→ VACUUM
→ physical/logical verify
→ SUCCESS
```

VACUUM, verification, or completion failure keeps STARTED pending. STARTED failure
in the logical transaction rolls back the request-log UPDATE.

### 5.4 Scrub tests

Prove:

- legacy audit schema migration succeeds before STARTED and the scrub completes;
- current event corruption fails with no STARTED, request-log mutation, or VACUUM;
- current state-head corruption has the same fail-closed result;
- current trigger corruption has the same fail-closed result;
- audit migration/preflight failure leaves request-log rows byte-for-byte and
  logically unchanged;
- exclusive ownership remains valid across the audit prerequisite, logical
  transaction, COMMIT, VACUUM, and completion transaction;
- BEGIN EXCLUSIVE precedes lookup;
- STARTED and logical clear rollback together;
- no unlocked lookup gap;
- WAL and rollback-journal erasure regressions remain green;
- VACUUM/verify/completion failures leave pending and no SUCCESS;
- dirty=0 pending work reuses TargetID and finishes;
- multiple pending fails before UPDATE/VACUUM;
- body/error canaries do not survive or enter AuditEvent.

## 6. Durable AtomicReplace and configaudit

`AtomicReplace` distinguishes:

```text
PRE_RENAME_FAILURE
POST_RENAME_DIRECTORY_SYNC_FAILURE
RESTORE_FAILURE
```

Approved result shape:

```go
type ReplaceResult struct {
    Renamed         bool
    DirectorySynced bool
}
```

Durable sequence:

```text
same-directory temp create
→ prior mode
→ complete write
→ file fsync
→ close
→ rename
→ open containing directory
→ directory fsync
→ close
```

Pre-rename error leaves target unchanged. Post-rename directory-sync error means
candidate may be visible and the coordinator must compensate. Restore uses the
same full sequence.

If restore rename occurs but restore directory fsync fails, return
`ErrConfigAuditRollbackFailed` and state that prior bytes may be visible while
durability is uncertain. Do not claim durable restore success.

Returned-error compensation is not process/power-loss atomicity. Tests use internal
seams/adapters, never a production debug or fault flag.

Tests cover pre-rename unchanged, successful durable result, post-rename result,
automatic exact-byte compensation, exact mode, restore sync failure, Apply/runtime
ordering, and privacy-safe errors.

## 7. Credential entropy fail-closed

Cover both:

```text
internal/handlers/setup.go
internal/config/config.go
```

Use one credential generator returning `(value, error)`. No crypto/rand error may
be ignored. All generation completes before config, runtime, session, or audit
mutation. Preserve bounded hexadecimal output.

Required cases:

1. Setup SessionSecret generation failure.
2. Setup Prometheus password generation failure.
3. Fresh/default config SessionSecret generation failure.
4. `ensureDefaults` SessionSecret generation failure.
5. `ensureDefaults` Prometheus generation failure.

Setup failures leave config bytes, runtime Admin/Prometheus state, sessions, and
audit unchanged. Bootstrap/default failures do not create or rewrite an empty
credential. Success output occurs only after persistence. No production fault flag
is allowed. Unrelated non-credential randomness is out of scope.

## 8. Reset-password

Operational contract:

```text
offline CLI path=enforced by dispatch-before-runtime
gateway must be stopped=operational precondition
restart required=operational contract
hot reload=unsupported
cross-process offline exclusivity=NOT IMPLEMENTED / NOT CLAIMED
```

CLI help, safe success output, README, and ADR-010 record this contract. The CLI
must not claim it can prove another process stopped.

Corrupt-current-audit tests cover event, state, and trigger corruption. Every case
requires:

```text
reset failure
config byte-identical
password hash unchanged
sessions unchanged
audit unchanged
no success output
no password material leak
no temp artifact
```

Keep current bounded TTY/stdin input, argv removal, session revocation, audit
privacy, and returned-error compensation.

## 9. Listener boundary

S2-NB1 is test-only:

```text
PRODUCTION_FILES_CHANGED_FOR_S2_NB1=0
startListeners production signature unchanged
verified capability token forbidden
production startup redesign forbidden
```

The integration test calls `runAuditPreflightThen`; its callback invokes the real
`startListeners` with concrete API/Admin/Metrics loopback addresses.

With current-corrupt audit:

- error is `AUDIT_INTEGRITY_CHECK_FAILED`;
- callback never reaches real listener binding;
- API, Admin, and Metrics addresses remain independently bindable;
- `CORRUPT_AUDIT_REAL_LISTENER_BIND_COUNT=0`.

Retain the static ordering gate:

```text
audit preflight
< dependency/router construction
< startListeners
```

## 10. Complete management-action matrix

| Action | Audit | Atomicity | Privacy | Slice 7 |
|---|---|---|---|---|
| Client create | `CLIENT_CREATED` | Same SQLite tx | Metadata only | Regression |
| Client rotate | `CLIENT_KEY_ROTATED` | Same SQLite tx | No key | Regression |
| Client suspend | `CLIENT_SUSPENDED` | Same SQLite tx | Bounded reason | Regression |
| Client resume | `CLIENT_RESUMED` | Same SQLite tx | Bounded reason | Regression |
| Client revoke | `CLIENT_REVOKED` | Same SQLite tx | No key/hash material | Regression |
| Client delete | `CLIENT_DELETED` | Same SQLite tx | Event survives no-FK delete | Regression |
| Login success | `ADMIN_LOGIN_SUCCEEDED` | Session+audit tx | No token | Regression |
| Logout | `ADMIN_LOGOUT` | Revoke+audit tx | No token | Regression |
| Failed login | Deliberately absent | N/A | Avoid unauthenticated write amplification | ADR policy |
| Setup | `SETUP_COMPLETED` | Config compensation + session/audit tx | No credentials | Entropy |
| Client settings | `CLIENT_SETTINGS_UPDATED` | Same SQLite tx | Metadata only | Regression |
| Client provider secret | `CLIENT_PROVIDER_SECRET_CHANGED` | Same SQLite tx | No secret | Regression |
| Client models | `CLIENT_MODELS_UPDATED` | Same SQLite tx | No payload | Regression |
| Server tools | `SERVER_TOOLS_UPDATED` | Config compensation | No list payload | AtomicReplace |
| Capture read | `REQUEST_BODY_CAPTURE_READ` | Audit before disclosure | No body | Document expiry race |
| Password reset | `ADMIN_PASSWORD_RESET` | Config compensation + session/audit tx | No password/hash | NB2/NB3 |
| Global provider key | `GLOBAL_PROVIDER_SECRET_CHANGED` | Config compensation | No key/envelope | AtomicReplace |
| Request-log scrub | Missing | Exclusive tx + post-commit VACUUM | No body/error | Two-phase closure |
| Provider migration | Missing | SQLite/config/backup state machine | No secret/path | Two-phase closure |

Failed login remains non-persistent as an unauthenticated write-amplification
defense. Provider migration and request-log scrub are the only remaining P1-08A
management-action gaps. No third missing action was found.

## 11. Viewer and retention

Viewer changes are limited to the four maintenance actions and:

```text
TargetType=maintenance-operation
```

Keep Admin authentication, read-only behavior, bounded pagination/filtering,
HTML escaping, and no-store. Do not add mutation, edit, delete, clear, prune,
export, arbitrary filtering, or unbounded listing.

Retention is:

```text
P1-08B retains audit events indefinitely.
No application/API delete, clear, prune, or retention mutation exists.
Future archival/rotation requires a separate design preserving chain evidence.
```

No prune subsystem belongs to Slice 7.

## 12. Documentation and truthful status

Implementation-branch documentation may state only:

```text
P1-08B implementation=COMPLETE
DELIVERY=VERIFYING
P1-08 overall=VERIFYING
```

Do not claim P1-08 overall COMPLETE, Production Gate PASS, P1 Completion Gate
PASS, P2 started, or final tag creation. Final COMPLETE requires independent review
and a separately authorized delivery phase.

ADR-010 and characterization/design updates record chain/maintenance protocol,
real commit points, config compensation/crash limits, provider STARTED-before-
backup ordering, scrub UPDATE/VACUUM/SUCCESS phases, failed-login policy,
capture-read expiry semantics, reset offline/restart contract, retention, and
viewer limits.

## 13. Expected files

Production:

```text
internal/audit/audit.go
internal/audit/maintenance.go
internal/database/database.go
internal/configstore/store.go
internal/configaudit/coordinator.go
internal/secretmigration/migrate.go
internal/requestlogscrub/scrub.go
internal/securegen/hex.go
internal/config/config.go
internal/handlers/setup.go
internal/handlers/audit_viewer.go
cmd/server/main.go
cmd/server/reset_password.go
```

`cmd/server/server.go` is not changed for S2-NB1. Unrelated production changes
are outside this plan.

Tests:

```text
internal/audit/p1_08a_audit_characterization_test.go
internal/audit/p1_08b_s7_maintenance_test.go
internal/database/p1_08b_s7_exclusive_test.go
internal/configstore/store_test.go
internal/configaudit/coordinator_test.go
internal/secretmigration/migrate_test.go
internal/secretmigration/preconditions_test.go
internal/requestlogscrub/scrub_test.go
internal/securegen/hex_test.go
internal/config/bootstrap_output_test.go
internal/handlers/p1_08b_s5_setup_test.go
internal/handlers/p1_08b_s5_static_gate_test.go
internal/handlers/p1_08b_s6_viewer_test.go
cmd/server/reset_password_test.go
cmd/server/p1_08b_s2_cli_test.go
cmd/server/listener_gate_test.go
```

Documentation:

```text
docs/adr/ADR-010-audit-integrity-and-management-events.md
docs/p1-08-audit-characterization.md
docs/superpowers/specs/2026-08-30-p1-08b-audit-integrity-design.md
docs/scope-v1.md
README.md
```

`go.mod` and `go.sum` remain unchanged.

## 14. Frozen implementation order

Each task starts with focused failing tests, proves red, implements only the
approved behavior, proves green, and commits a coherent checkpoint only after its
acceptance criteria pass.

1. Maintenance audit module/tests.
2. Durable AtomicReplace/configaudit.
3. Request-log scrub two-phase audit.
4. Provider migration two-phase audit.
5. Secure credential generator.
6. Reset contract and corrupt-audit regression.
7. Listener test-only strengthening.
8. Viewer/static/privacy gates.
9. ADR-010, characterization, design, and truthful scope.
10. Full local gates.
11. Commit.
12. Push same branch.
13. Stop.

No task may weaken a Gate, add a production fault flag, alter the canonical hash,
broaden the viewer, or refactor unrelated systems.

## 15. Local gates

Format every tracked and new Go file explicitly, then run:

```bash
go test ./internal/audit -count=1
go test ./internal/configstore ./internal/configaudit -count=1
go test ./internal/secretmigration -count=1
go test ./internal/requestlogscrub -count=1
go test ./internal/config ./internal/handlers ./cmd/server -count=1

go test ./internal/audit \
  -run '^TestP108B_S1_ConcurrentAppendNoFork$' -count=20

go test -race ./internal/audit \
  -run '^TestP108B_S1_ConcurrentAppendNoFork$' -count=5

go test ./internal/configaudit -count=20
go test ./internal/secretmigration -run '^TestP108B_S7_' -count=20
go test ./internal/requestlogscrub -run '^TestP108B_S7_' -count=20

go test ./... -count=1
go vet ./...
go test -race ./... -count=1
bash scripts/verify.sh
git diff --check
git diff -- go.mod go.sum
git status --short
```

Required report:

```text
TARGETED_TESTS=PASS
FULL_TEST=PASS
VET=PASS
RACE=PASS
VERIFY=PASS
CONCURRENT_20X=PASS
CONCURRENT_RACE5=PASS
CONFIGAUDIT_20X=PASS
MIGRATION_20X=PASS
SCRUB_20X=PASS
DIFF_CHECK=PASS
GO_MOD_CHANGED=false
GO_SUM_CHANGED=false
```

Any acceptance, race, privacy, migration, SQLite, config-compensation, or
verification failure stops implementation. Do not weaken tests or standards.

## 16. Review delivery

```text
implement
→ local gates
→ commit on task/p1-08b-audit-logging
→ push SAME task branch normally
→ STOP
```

Luna does not create a PR, merge, tag, push develop/main, or start P2. Force push
and force-with-lease are forbidden.

The independent reviewer compares:

```text
LUNA_SLICE7_IMPLEMENTATION_BASE
→ NEW_HEAD
```

and reviews commit, complete diff, production code, tests, docs, privacy, and CI
eligibility. PR/CI/merge/fresh-clone/tag require separate authorization.
