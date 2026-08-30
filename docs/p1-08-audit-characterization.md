# P1-08A Audit Logging Characterization

**Baseline:** `0f05fc08dec53adb6b9e6e31011d6a2561596682` (P1-07B merge)

**Scope:** tests and documentation only. This stage records the behavior that exists at the baseline; it does not add production audit actions or database integrity controls.

## Conclusion

The repository has a useful P1-05C audit foundation, but it is not yet a complete immutable management audit subsystem.

- The six client-key lifecycle mutations write one minimal `AuditEvent` in the caller's SQLite transaction.
- `AuditEvent` has no client foreign key, so a client deletion does not delete its audit history.
- The application service exposes append and list only, but SQLite currently permits direct `UPDATE` and `DELETE` of `audit_events`.
- Login, setup, configuration, diagnostics, secret provisioning/migration, and request-log scrubbing are not represented by audit events.
- There is no database trigger, hash chain, startup verification, offline verification command, retention policy, or management viewer at this baseline.

This is the characterization boundary for P1-08A. P1-08B owns the implementation of the missing controls.

## Current flow

```text
Admin HTTP / setup / CLI operation
    ├─ client lifecycle service mutation
    │      └─ RecordTx(tx, AuditEvent) in the same SQLite transaction
    └─ config-file, diagnostic, or offline operation
           └─ no AuditEvent at this baseline

audit_events
    └─ application List only; database owner can still mutate rows
```

The authoritative production write sites are the six `s.audit.RecordTx` calls in `internal/services/client.go`. The action whitelist is in `internal/audit/audit.go`; it contains only those six lifecycle actions.

## Schema and API characterization

| Area | Current behavior | Evidence |
|---|---|---|
| Columns | `id`, `event_id`, `action`, `actor_type`, `actor_id`, `target_type`, `target_id`, bounded `reason`, `created_at` | `internal/models/audit_event.go`; `TestP108A_AuditEventSchemaIsMinimalAndUnlinked` |
| Secret/body fields | No API key, provider key, authorization, request body, arbitrary payload, or metadata column | model definition and schema characterization test |
| Event identity | Server-generated UUIDv4 with a unique index | `internal/audit/audit.go` and existing `internal/audit/audit_test.go` |
| Target relationship | No foreign key to `clients` | model definition and `PRAGMA foreign_key_list` characterization |
| Write API | `Service.RecordTx` validates fixed actions and writes through the caller's transaction | `internal/audit/audit.go` |
| Read API | `Service.List` reads events for a target in ascending row order | `internal/audit/audit.go` |
| Application surface | No `Update` or `Delete` method on `audit.Service` | `internal/audit/audit.go` |
| Database enforcement | Direct database update/delete currently succeeds; no `audit_events` trigger exists | `TestP108A_ApplicationAppendOnlyDoesNotImplyDatabaseImmutability` and `TestP108A_AuditEventSchemaIsMinimalAndUnlinked` |

The no-FK choice is intentional: `CLIENT_DELETED` must survive deletion of the client row.

## Management-action coverage

### COVERED

| Action | Current event | Atomicity / evidence |
|---|---|---|
| Client create | `CLIENT_CREATED` | Client row, encrypted client settings, and event share one transaction; existing P1-05C lifecycle tests cover success and rollback. |
| Client API-key rotate | `CLIENT_KEY_ROTATED` | New hash and event share one transaction; existing P1-05C tests cover success and revoke race. |
| Client suspend | `CLIENT_SUSPENDED` | State mutation and event share one transaction. |
| Client resume | `CLIENT_RESUMED` | State mutation and event share one transaction. |
| Client revoke | `CLIENT_REVOKED` | Terminal state, NULL API-key hash, metadata, and event share one transaction. |
| Client delete | `CLIENT_DELETED` | Event is inserted before cleanup/deletion in the same transaction and remains after client deletion because there is no FK. |

The existing `internal/handlers/p1_05c_lifecycle_test.go` verifies lifecycle event cardinality, actor/reason fields, deletion retention, secret canaries, and audit-insert rollback. `internal/audit/p1_08a_audit_characterization_test.go` adds schema, caller-transaction, whitelist, and direct-database-integrity characterization.

### MISSING

The following operations are reachable management or operational actions at the baseline but have no corresponding `AuditEvent` action or audit write:

| Operation | Relevant code path | Current evidence / risk |
|---|---|---|
| Admin login success | `internal/handlers/admin.go:HandleLogin` | Session creation is not audited. |
| Admin logout | `internal/handlers/admin.go:HandleLogout` | Session revocation is not audited. |
| Failed admin login | `internal/handlers/admin.go:HandleLogin` plus login limiter | Runtime logging/limiting exists, but no persistent audit event; repeated failures therefore do not currently create persistent audit write amplification. |
| Setup completed | `internal/handlers/setup.go:HandleSetup` | Config candidate is saved, but completion is not audited. |
| Client settings update | `internal/handlers/admin.go:UpdateClient` → `UpdateClientSettings` | Deliberately excluded from the P1-05C lifecycle whitelist; no event records provider/model setting changes. |
| Client provider key set/clear | client creation/update settings path | Secret mutation has no dedicated event. The event must contain metadata only, never the key. |
| Client models update | `UpdateClientModels` and admin model update path | No event records the bounded model-list mutation. |
| Server tools update | `UpdateServerTools` | Config mutation is not audited. |
| Diagnostic request-body read | `GetCapturedRequestBody` | A privileged read of memory-only diagnostic content is not audited. |
| Admin password reset | `cmd/server/main.go:-reset-password` | Offline config mutation is not audited. The current CLI also accepts the new password as an argument; eliminating argv secret exposure is a later hardening concern. |
| Global provider key set/replace | `cmd/server/provision.go` and `cmd/server/main.go` | Secure provisioning changes config but emits no event. |
| Request-log scrub | `cmd/server/main.go:-scrub-request-log-content` | Irreversible offline scrub is not audited. |
| Provider-secret migration | `cmd/server/main.go:-migrate-provider-secrets` | Offline migration is not audited. |

These labels are characterization names, not newly introduced production constants. The whitelist test deliberately asserts that they are unsupported at P1-08A.

### OUT-OF-SCOPE for P1-08A

- Adding new production actions or changing handler/service behavior.
- Database triggers that reject `UPDATE`/`DELETE` of audit rows.
- Hash-chain fields, canonical serialization, chain-head storage, or tamper-evidence verification.
- Startup or offline audit verification commands.
- Admin audit viewer, pagination, filtering, export, or authorization UX.
- Retention/deletion policy for audit history.
- Changing the existing six lifecycle action contract.
- Production release review, signed release tags, or P1-07/P1-08B work.

## Atomicity and failure behavior

For the six lifecycle operations, `RecordTx` receives the transaction owned by the service method. An audit insert error rolls back the preceding lifecycle mutation; the P1-05C suite injects an audit-table failure and verifies rollback. A normal caller transaction also rolls back a `RecordTx` event, as captured by the new characterization test.

This atomicity does not extend to config-file or offline operations. Setup, password reset, provider-key provisioning/migration, and request-log scrubbing use config or offline storage workflows rather than the client SQLite transaction. No config mutation + audit event transaction contract exists yet.

## Privacy and actor boundary

The current model and `RecordTx` validation bound actor/target/reason fields and reject control characters. The event model has no secret or body payload fields. Existing P1-05C canary tests show that lifecycle key material and provider-secret canaries do not appear in audit rows. Lifecycle actor identity is supplied by the trusted admin configuration path, not by an untrusted form field.

This evidence applies to the six implemented lifecycle events. Missing management actions have no event contract yet, so P1-08A does not claim their future actor, reason, or privacy behavior.

## Integrity gap

At this baseline, “append-only” means an application convention:

1. `audit.Service` offers `RecordTx` and `List`, not update/delete methods.
2. Production lifecycle code uses `RecordTx` for the six fixed actions.
3. Nothing at the SQLite schema boundary prevents an operator, migration, or compromised process with database write access from changing or deleting rows.

There are no `audit_events` immutability triggers, hash-chain columns, canonical event digest, trusted chain-head record, startup verification, offline verification, or retention controls. The database integrity boundary is therefore explicitly incomplete and remains a P1-08B acceptance item.

## P1-08B handoff

P1-08B may use this document and the characterization tests as its baseline contract. It must define and test the database-level immutability/tamper-evidence design, complete management-action coverage, and verification/viewer behavior without introducing secret or request-body payloads into audit records. Any change to the six P1-05C lifecycle semantics requires a separate scope decision.
