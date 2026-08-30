# ADR-009：Public Request Validation Boundary

- Status: Accepted
- Date: 2026-08-30
- Scope: P1-07B public API request validation
- Baseline: P1-07A merge `dc2db17c18f93b37ee2b86ac284f7da01ab27888`

## Context

Before P1-07B, the public API had a global `MaxBytesReader`, but JSON/media/schema checks were split between handlers. OpenAI happened to reject some malformed shapes through `json.Unmarshal`; Gemini could forward malformed JSON and unsupported encodings to upstream. Oversized generative bodies could also be consumed by the P1-06B quota middleware and surfaced as a quota/configuration error instead of a stable body-limit response.

The gateway must keep rate limiting ahead of validation for abuse resistance, while ensuring invalid requests do not reserve or consume daily quota and never reach a provider.

## Decision

The public API pipeline is:

```text
Auth
  → Rate Limit
  → Request Validation
  → Daily Quota
  → Handler
  → Upstream
```

`RequestValidation` is a shared middleware in `internal/middleware/request_validation.go`. For registered public POST body routes it:

1. validates `Content-Type: application/json` (including media-type parameters);
2. rejects non-identity `Content-Encoding` with 415;
3. performs one bounded body read using the 10 MiB hard cap and maps overflow to 413 `REQUEST_TOO_LARGE`;
4. rejects invalid UTF-8, malformed JSON, trailing JSON values, non-object top-level values and nesting deeper than 64;
5. validates protocol minimums without `DisallowUnknownFields`:
   - OpenAI-compatible and `/v1/messages`: non-empty bounded model, non-empty object messages, string role when present, boolean stream when present, bounded non-negative output-token fields;
   - Gemini native: path model, non-empty object contents/parts, string part text when present, bounded generation output tokens;
   - `count_tokens`: object body and string prompt when present;
6. applies the existing conservative byte-based `MaxInputTokens` bound before quota reservation;
7. writes only bounded stable error codes/messages and never echoes the request body;
8. stores the validated body in request context.

Quota and handlers consume the context body through `ReadRequestBody`; they do not independently read the inbound stream in the production public pipeline. Direct handler callers retain a fallback read for compatibility with existing unit seams.

## Bounds and compatibility

The chosen bounds are:

- body: 10 MiB (`10 << 20` bytes);
- JSON nesting: 64 container levels;
- model: 200 Unicode runes, valid UTF-8, no Unicode control characters;
- messages, contents and parts: at most 4,096 items each;
- declared protocol output tokens: at most 1,000,000, non-negative integer, and never above the client output limit.

Unknown extension fields remain accepted. Model names are not restricted by a narrow regular expression, so provider identifiers containing `/`, `-`, `_`, `:`, and `.` remain valid.

Duplicate JSON object fields remain accepted with the standard decoder's last-value-wins behavior; P1-07B does not claim duplicate-key rejection.

`/v1/messages/count_tokens` is validated as a bounded JSON endpoint but remains non-generative and outside P1-06B daily quota reservation. GET model and health routes do not enter request-body validation.

## Error contract

Validation failures use JSON:

```json
{"error":{"code":"<STABLE_CODE>","message":"<BOUNDED_MESSAGE>"}}
```

The main status mapping is 413 for body overflow, 415 for unsupported media/encoding, and 400 for JSON/protocol violations. The existing server-generated RequestID middleware runs before this boundary, so validation responses retain `X-Request-ID`.

## Alternatives rejected

- Handler-local validation: rejected because it permits protocol drift and repeated body reads.
- Validation before rate limiting: rejected because malformed traffic could avoid consuming abuse-control capacity.
- `json.Decoder.DisallowUnknownFields`: rejected because provider and client extensions are part of compatibility.
- Exact token counting in the gateway: rejected for this phase because no reliable shared tokenizer exists; request input enforcement continues to use the documented conservative byte upper bound.
- Transparent request decompression: rejected for V1; unsupported compression is explicitly rejected to avoid decompression-bomb and ambiguous size semantics.

## Verification

P1-07B tests cover body cap for known/chunked bodies, media/encoding errors, malformed/trailing/top-level/deep JSON, protocol field types, model controls, token bounds, unknown extensions, valid streaming, context body reuse, public upstream-call canaries, RequestID preservation, and P1-04/P1-05/P1-06 regressions.
