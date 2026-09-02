# ADR-010: Audit Integrity and Management Events

**Status:** accepted; P1-08B implementation complete, delivery verifying

**Date:** 2026-09-02

**Scope:** P1-08B audit logging enforcement

## Context

P1-08A established that the original AuditEvent model was only an application
append-only convention. The six client lifecycle events had transaction-local
rollback, but database rows could still be edited or deleted and most
management operations had no audit event. This ADR records the implemented v1
integrity boundary and the operational limits that remain explicit.

## Decision

### v1 event chain

AuditEvent keeps bounded metadata only. Each new event stores:

- ChainVersion, fixed to v1;
- PrevHash, empty only for genesis;
- EventHash, lowercase SHA-256;
- the existing event identity, action, actor, target, reason, and UTC timestamp.

The canonical input is a fixed, non-JSON byte sequence:

~~~text
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
~~~

Each field is encoded as its UTF-8 byte length in decimal, a colon, and the
exact UTF-8 bytes, followed by the literal separator. CreatedAt is normalized
to UTC and hashed using its UnixNano value after database round-trip
verification. No map or JSON ordering is part of the protocol.

AuditChainState is a singleton row with id 1, chain version, head hash, and
updated timestamp. It is the serialization state, not a second event history.
VerifyAuditChain validates every event in immutable ID order and also requires
the state head to equal the final EventHash, or to be empty for an empty chain.

### Serialization and database immutability

RecordTx requires a real active SQL transaction. It cannot open a nested
transaction or accept a non-transactional database handle. Within the caller's
SQLite write transaction it:

~~~text
UPDATE chain state with a no-op write
→ SELECT state and current tail
→ validate state/tail consistency
→ generate event identity/timestamp and canonical hash
→ INSERT event
→ UPDATE singleton head
→ COMMIT by the transaction owner
~~~

The no-op state write obtains the SQLite writer lock before the head is read.
Independent database connections therefore serialize appenders through SQLite;
an in-process mutex is not the integrity mechanism.

The dedicated audit migration owns the chain schema. It runs in one transaction:
additive schema migration, deterministic ID-ascending legacy backfill, chain
verification, exact trigger-definition validation/installation, then commit.
Only a completely unchained legacy history or a fully valid chained history is
accepted. Mixed, partial, corrupt, or unsupported states fail closed; migration
does not silently repair them. Existing event timestamps and semantics are
preserved. The initial backfill is a cryptographic baseline, not proof about
modifications made before the chain existed.

UPDATE and DELETE triggers reject direct changes to audit events. The boundary
does not protect against a root or database owner who can replace the database,
alter its schema, or remove the triggers.

### Startup and offline verification

Normal startup performs the dedicated audit migration and verification before
constructing or binding public, Admin, or metrics listeners. A corrupt or
unsupported audit state returns the stable integrity failure and startup
remains fail closed.

The verify-audit-log command uses a separate read-only database open path. It
does not run AutoMigrate, backfill, trigger installation, config persistence,
or listener setup. A legacy database that needs migration returns an explicit
audit schema/migration required failure instead of being modified.

### Management actions and trusted identity

The six existing lifecycle actions remain unchanged and retain their
same-transaction semantics. The completed management action set is:

~~~text
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
~~~

Admin actors come from the trusted authenticated session/configuration boundary,
never from a form, query, header, or request body. CLI maintenance actors use
actor_type=cli. Maintenance targets use a server-generated UUID and
target_type=maintenance-operation; the UUID is correlation data and is never
accepted as CLI/user input.

Successful actions append exactly one corresponding success event. Failed
ordinary mutations do not append success. A maintenance operation may retain
one durable STARTED event while pending recovery; completion uses the same
target ID and does not create a second operation.

### Provider-secret migration

Provider migration spans SQLite, configuration, and recovery-backup files, so
it cannot be one cross-storage transaction. Its durable protocol is:

~~~text
audit schema/integrity prerequisite
→ STARTED audit event committed
→ recovery backup containing current database/audit state
→ PREPARE and VERIFY provider mutations
→ config FINALIZE plus SQLite client FINALIZE/SUCCESS
→ commit/verify the ordered operation
~~~

The STARTED event is written before the backup. If the audit prerequisite or
STARTED append fails, no provider recovery backup or provider mutation is
performed. A backup failure may leave pending STARTED evidence. A later run
uses the existing pending target ID, rejects multiple pending operations, and
only reports success after final persistence and verification. No secret
material is placed in an event; the backup is the recovery artifact, not an
audit payload.

The final configuration rename and SQLite finalization are ordered and
compensated, but are not a single transaction. A crash between storage commit
points can leave a pending operation and must be recovered or reported as
failure; the implementation does not claim power-loss atomicity.

### Request-log scrub

Scrub is an offline destructive maintenance operation. It obtains ownership
through an exclusive SQLite connection/transaction, performs pending lookup,
resume/new selection, and STARTED append inside that authoritative boundary,
then commits the logical content update. VACUUM and physical/logical
verification follow the logical commit, after which the terminal scrub event
is appended. The exclusive ownership is held continuously through the
post-update checkpoint/verification boundary. The scrub is irreversible and
has no online gateway-stop proof; operational invocation must be offline.

### Configuration replacement and compensation

Config AtomicReplace writes and fsyncs a temporary file, renames it, then
fsyncs the containing directory. Its failure contract is explicit:

- PRE_RENAME_FAILURE: the old file remains authoritative and no success event
  is reported;
- POST_RENAME_DIRECTORY_SYNC_FAILURE: rename already happened, so compensation
  restores the prior bytes and reports the stable failure;
- RESTORE_FAILURE: fail closed with the stable compensation error and do not
  report success.

When a config-backed audit append fails, the prior configuration is restored
byte-for-byte. These guarantees address the observed operation and recovery
paths; they do not create a cross-storage transaction or a power-loss proof.

### Credentials, login, capture, and reset

The capture-read contract is:

~~~text
capture exists
→ audit REQUEST_BODY_CAPTURE_READ
→ re-check capture
→ disclose only if still available
~~~

If the capture expires during the audit operation, the HTTP result is 404,
BODY_DISCLOSED=false, and AUDIT_EVENT_REMAINS=true. The event proves that the
privileged read crossed the audit boundary; it does not guarantee that the body
was ultimately disclosed. The audit event contains no request body.

Credential generation uses one crypto/rand-backed bounded generator. Session
secret and Prometheus password generation errors are fail closed: config,
runtime state, and audit history remain unchanged, and no success output is
emitted before persistence.

Successful admin login and logout are audited. Failed login attempts are
deliberately not persisted; rate limiting remains the abuse-control boundary.
The capture-read event is appended before the privileged in-memory request body
is disclosed. The body, headers, credentials, and arbitrary payload are never
copied into the audit event.

Password reset is an offline CLI contract. The gateway must be stopped, a
restart is required before use, and hot reload is unsupported. The implementation
does not claim to prove that a separately running gateway process has stopped;
cross-process offline exclusivity remains an operational precondition.

### Viewer and retention

GET /admin/audit is Admin-authenticated, read-only, no-store, HTML-escaped, and
bounded to at most 100 rows per page. Keyset pagination and only these typed
filters are exposed:

~~~text
before_id, limit, action, actor_type, actor_id, target_type, target_id
~~~

There are no timestamp filters and no update, delete, clear, prune, or export
surface. Audit retention is indefinite in v1. Any future archive or retention
policy requires a separate design and integrity review.

## Consequences

The gateway can detect in-scope event edits, deletes, broken links, and a
damaged chain-state head before serving traffic. Management history survives
client deletion because events have no client foreign key. Failure states for
filesystem-backed maintenance are explicit pending or compensated outcomes,
not false claims of atomic success.

The design intentionally does not claim a single transaction across SQLite,
configuration, backups, and VACUUM, nor protection against a privileged owner
who can replace or rewrite the database. It also does not claim hot reset or
cross-process stop enforcement.

## Verification evidence

P1-08B tests cover independent-connection append serialization, legacy
backfill/order/timestamp preservation, mixed/partial fail-closed migration,
trigger integrity, startup listener boundary, read-only verification,
management audit rollback, config replacement compensation, entropy failure,
maintenance pending/resume behavior, scrub ownership, privacy canaries, and
viewer authorization/filtering/escaping. Final delivery remains a separate
verification state until the authorized review and integration gates complete.
