# P1-08B Audit Integrity Enforcement Design

**Status:** approved design for implementation

**Baseline:** `develop@ce2b85480500a898b282dac079375260b29ba52f`

**Task:** `P1-08B`

**Branch:** `task/p1-08b-audit-logging`

**Final tag:** `secure-gateway-p1-audit-logging`, created only after the final merge and fresh-clone verification

## Goal and boundary

P1-08B completes the existing P1-05C `AuditEvent` foundation into a tamper-evident, fail-closed audit subsystem while preserving the six existing client lifecycle events and their same-transaction semantics.

The implementation includes the audit chain, SQLite writer serialization, deterministic legacy backfill, database mutation guards, startup and offline verification, management-action coverage, trusted actors, privacy boundaries, configuration rollback, and a bounded read-only viewer.

It does not claim protection from a root/database owner who can replace the database, drop triggers, or rewrite the entire file. It does not include P1 Completion Gate, P2, production release, main reconciliation, or unrelated cleanup.

## Existing source of truth

- `internal/models/audit_event.go` is the existing generic event model.
- `internal/audit/audit.go` owns fixed action validation, append, and list behavior.
- `internal/services/client.go` owns the six lifecycle mutations and currently passes their audit insert through the same GORM transaction.
- `cmd/server/main.go` owns startup migration and CLI dispatch.
- `internal/handlers/admin.go` and `internal/handlers/setup.go` own Admin HTTP mutations and diagnostics.
- `docs/p1-08-audit-characterization.md` records the P1-08A baseline and must be updated with the resolution evidence.

No second audit subsystem or lifecycle event table will be introduced.

## Frozen Implementation Clarifications

The following rules are binding for Slice 1 and all later slices:

A. Migration accepts only `LEGACY_ALL_UNCHAINED` or `FULLY_CHAINED_VALID`. Mixed or partial chain data, missing state for chained events, or state without a fully chained event history is corruption and must fail closed. Migration must never silently repair those states.

B. Generic `autoMigrate` owns ordinary business tables only. It must not add `AuditEvent` chain columns outside the dedicated audit migration transaction, which owns `AuditEvent`, `AuditChainState`, deterministic backfill, verification, and trigger installation.

C. `RecordTx` requires a real active SQL transaction and returns `ErrAuditTransactionRequired` otherwise. A separate `Record` entry point opens and commits its own transaction; `RecordTx` never opens a nested transaction.

D. After the SQLite writer lock is acquired, append validates the singleton state against the current tail before creating an event. A state/tail mismatch aborts the append and cannot be overwritten by a new event.

E. `VerifyAuditChain` validates exactly one `AuditChainState` row with `id=1`, supported version `v1`, valid head format, and head equality with the final event hash (or empty head for empty history).

F. Existing trigger names with definitions that do not exactly match the expected mutation guards are integrity failures. Migration must not silently accept or repair a suspected tampered trigger.

G. The v1 canonical timestamp is `CreatedAt.UTC().UnixNano()`. A test must prove that generating, inserting, closing, reopening, and reloading SQLite preserves the same UnixNano and EventHash; a precision mismatch stops the stage rather than changing the protocol.

H. Legacy backfill establishes the initial cryptographic baseline for accepted pre-P1-08B rows. It does not provide retroactive proof that those rows were never modified before the chain existed.

## Data model

`AuditEvent` keeps all existing fields and adds:

| Field | Type | Meaning |
|---|---|---|
| `ChainVersion` | bounded string | Protocol version, fixed to `v1` for this stage |
| `PrevHash` | lowercase hex string | SHA-256 hash of the immediately preceding event, empty only for genesis |
| `EventHash` | lowercase hex string | SHA-256 digest of the canonical event encoding |

The fields are additive and nullable at the SQL migration boundary so pre-P1-08B rows can be read and backfilled without deleting or changing their event meaning. New appends must always populate all three values and reject unsupported chain versions.

`AuditChainState` is a singleton table with a stable row identifier `id=1`, `chain_version`, `head_hash`, and `updated_at`. Its row is the database serialization point and is not an alternative event history.

Genesis is represented by `AuditChainState.head_hash == ''` before the first event. The first event has `PrevHash == ''`; after each successful append, the state row head equals that event's `EventHash`.

## Canonical encoding and hashing

The hash input is not JSON and never contains a Go map. It is a fixed byte sequence:

```text
AUDIT-EVENT-V1|
field(ChainVersion)|
field(PrevHash)|
field(EventID)|
field(Action)|
field(ActorType)|
field(ActorID)|
field(TargetType)|
field(TargetID)|
field(Reason)|
field(CreatedAtUnixNano)
```

`field(s)` is the UTF-8 byte length in base-10, followed by `:`, followed by exactly those UTF-8 bytes. The final separator is literal `|`. `CreatedAtUnixNano` is the base-10 representation of `CreatedAt.UTC().UnixNano()`. The timestamp stored in the row is normalized to UTC before hashing. The event hash is lowercase hexadecimal SHA-256 of the complete byte sequence.

This encoding binds, in a fixed order, `ChainVersion`, `PrevHash`, `EventID`, `Action`, `ActorType`, `ActorID`, `TargetType`, `TargetID`, `Reason`, and `CreatedAt`. Length-prefixing prevents delimiter ambiguity and makes the representation independent of JSON/map ordering.

## Append serialization

Every append runs in one SQLite write transaction:

```text
BEGIN transaction
→ UPDATE audit_chain_states SET head_hash=head_hash WHERE id=1
  (the first write obtains SQLite's writer lock)
→ SELECT the singleton state row and the ordered current tail
→ derive PrevHash from the locked state/tail
→ generate server EventID and UTC CreatedAt
→ calculate EventHash from canonical bytes
→ INSERT AuditEvent
→ UPDATE singleton head to EventHash
→ COMMIT
```

The state-row write occurs before reading the head. No implementation may use an unlocked `SELECT last hash → INSERT` sequence. SQLite busy/lock errors are returned as stable audit errors; no partial event or head update is treated as success. The SQLite opener will retain foreign-key enforcement and configure a bounded busy timeout so independent connections serialize rather than silently forking.

`VerifyAuditChain` reads events in immutable primary-key order (`id ASC`) and checks both the event links and the singleton head. It must reject a chain when any event content, hash, previous hash, order, middle row, genesis value, chain version, or state head is inconsistent.

## Migration and trigger order

Startup migration uses an explicit transaction for the audit upgrade:

```text
BEGIN
→ additive schema migration for chain columns and chain-state table
→ ensure singleton state row exists with v1 / empty head
→ classify history as LEGACY_ALL_UNCHAINED or FULLY_CHAINED_VALID
→ reject mixed/partial history or incomplete state as corruption
→ for LEGACY_ALL_UNCHAINED, read events in deterministic id ASC order
  and preserve every existing field and timestamp while building the full v1 chain
→ for FULLY_CHAINED_VALID, do not backfill; verify the existing chain and state
→ establish or verify chain-state head against the final event hash
→ install missing UPDATE and DELETE reject triggers; validate existing definitions exactly
→ COMMIT
```

The existing immutable primary key `AuditEvent.ID` is the migration order. `CreatedAt` is hashed as stored but is never used alone to order history, and no historical timestamp or event semantic is rewritten. If any step fails, the migration transaction rolls back; triggers are installed only after backfill verification.

The triggers reject direct `UPDATE audit_events` and `DELETE FROM audit_events` with a stable integrity error. Normal `INSERT` from the append path remains allowed. This is database-level mutation guarding plus tamper-evident chaining, not protection against a database owner who can alter schema or replace the file.

## Verification boundaries

### Startup

Normal startup runs audit schema migration/backfill, trigger installation, and chain verification before constructing or serving public, Admin, or metrics listeners. Any corruption or unsupported chain version returns `AUDIT_INTEGRITY_CHECK_FAILED`; startup does not repair, rewrite, delete, or ignore corrupt data.

### Offline CLI

`-verify-audit-log` uses a separate read-only database open path. It does not call normal startup migration, backfill, trigger installation, config persistence, or listener setup. An un-migrated legacy database returns a stable “audit schema/migration required” failure. Success prints only verification status, event count, and a safe digest summary; corruption exits non-zero without dumping event content.

## Management audit coverage and actor policy

The implementation covers the six existing lifecycle actions plus:

```text
CLIENT_SETTINGS_UPDATED
CLIENT_PROVIDER_SECRET_CHANGED
CLIENT_MODELS_UPDATED
SERVER_TOOLS_UPDATED
ADMIN_LOGIN_SUCCEEDED
ADMIN_LOGOUT
SETUP_COMPLETED
REQUEST_BODY_CAPTURE_READ
ADMIN_PASSWORD_RESET
GLOBAL_PROVIDER_SECRET_CHANGED
PROVIDER_SECRET_MIGRATION_STARTED
PROVIDER_SECRET_MIGRATION
REQUEST_LOG_SCRUB_STARTED
REQUEST_LOG_SCRUB
```

Admin HTTP actions derive actor identity from the authenticated server-side session/configuration boundary. They never accept actor fields from form, query, headers, or request JSON. CLI actions use `ActorType=CLI` or `ActorType=SYSTEM` with a deterministic safe identifier. Failed login attempts remain non-persistent and rate-limited to avoid unauthenticated audit write amplification; the ADR records this deliberate policy.

Each successful action is appended exactly once. Failed operations do not append success events.

Provider-secret migration and request-log scrub use a durable STARTED event and
a terminal operation event. The actor is trusted CLI context, and the target is
a server-generated UUID of type maintenance-operation; the target is never
supplied by a user. Pending lookup, the resume/new decision, and the STARTED
append are performed inside the operation's authoritative serialization
boundary. Multiple pending operations fail closed, while a rerun resumes the
existing target instead of creating a second operation.

## Atomicity

SQLite-backed mutations append their event through the same transaction, including client settings, provider-secret set/clear, models, and lifecycle operations. Audit INSERT fault injection must prove the business mutation rolls back and no success event remains.

Config-file-backed mutations use a compensating protocol because a filesystem write cannot join a SQLite transaction:

```text
capture prior config bytes/state
→ atomically persist intended config
→ append audit event in SQLite
→ if audit append fails, restore prior bytes exactly
→ if restoration fails, fail closed with a safe error and do not report success
```

A config persistence failure produces no success event. Tests inject both post-write audit failure and config-write failure.

Provider-secret migration has the following durable ordering:

~~~text
audit schema and integrity prerequisite
→ committed PROVIDER_SECRET_MIGRATION_STARTED
→ recovery backup containing the current database/audit state
→ prepare and verify provider mutations
→ final config persistence plus SQLite client finalization
→ committed PROVIDER_SECRET_MIGRATION success
~~~

The backup is not created if the integrity prerequisite or STARTED append
fails. A backup failure may leave a pending STARTED operation; a later run
reuses its target ID and fails closed unless recovery can complete. The SQLite
and configuration/backup steps are not one cross-storage transaction, so crash
windows are represented by pending state and compensation rather than a false
claim of atomicity.

Request-log scrub obtains offline exclusive SQLite ownership, appends
REQUEST_LOG_SCRUB_STARTED and commits the logical scrub, then performs VACUUM
and physical/logical verification before appending the terminal event. The
destructive scrub is not reversible. Configuration AtomicReplace fsyncs the
file, renames it, and fsyncs its containing directory; a post-rename directory
sync failure enters compensation, including an explicit restore-failure error.

## Privacy boundary

Audit rows contain only bounded metadata and reason. They never contain plaintext or hashed API keys, provider/master secrets, Authorization, cookies, sessions, CSRF tokens, prompts, responses, request bodies/headers, config dumps, arbitrary payloads, or raw upstream errors. Diagnostic capture reads record only actor/action/safe target/timestamp, never the captured body. Secret canaries scan database rows and raw database files.

## Viewer

`GET /admin/audit` is Admin-authenticated, read-only, `Cache-Control: no-store`, and uses bounded keyset pagination with a maximum page size of 100. The only filters are the exact typed fields `before_id`, `limit`, `action`, `actor_type`, `actor_id`, `target_type`, and `target_id`; timestamp filters are not exposed. No SQL-like filter, mutation route, clear/delete/update control, or non-schema payload is exposed.

## Slice sequence

All slices remain one `TASK_ID=P1-08B`, one branch, and one PR. A slice may have several small commits but cannot be declared stage-complete or tagged independently.

1. Schema, canonical encoding, chain-state, serialized append, legacy backfill, mutation triggers, and `VerifyAuditChain`.
2. Startup fail-closed and read-only `-verify-audit-log`.
3. SQLite-backed management actions, trusted actors, and rollback tests.
4. Config-backed mutation protocol, exact restoration, and fault injection.
5. Login/logout/setup/capture-read, password stdin/TTY, and privacy canaries.
6. Read-only Admin viewer and static regression gates.
7. ADR-010, characterization resolution, scope truthfulness, and full local
   verification. Delivery review, PR/CI, merge, fresh-clone verification, and
   the final annotated tag are separate authorized closure steps.

## Stop conditions

Stop and report if SQLite writer serialization cannot be proven across independent connections, deterministic legacy backfill cannot preserve existing event semantics, config restoration cannot be proven byte-for-byte, startup verification cannot fail closed before listeners, or any change would require production behavior outside this scope. Do not lower a Gate or start P1 Completion Gate/P2.
