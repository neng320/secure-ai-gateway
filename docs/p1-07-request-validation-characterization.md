# P1-07 · Request Validation Characterization and Enforcement

> P1-07A 基线：`origin/develop` `b8c88816eff8a10920ee16a6fe88de8c8d31a7b8`（P1-06B.1 correction complete）。
> P1-07A 已合入 develop：`dc2db17c18f93b37ee2b86ac284f7da01ab27888`。
> 当前 P1-07B 分支：`task/p1-07b-request-validation-enforcement`。
> P1-07A 阶段只做审计、characterization tests 与文档，生产行为修改数 = 0；P1-07B enforcement 结果记录在 §8。

## 1. 公网请求数据流

```text
Public API router
  → Recovery
  → SecurityHeaders
  → MaxRequestSize(10 << 20) = 10,485,760 bytes
  → RequestID
  → /health, /health/ready, /health/live
  → authenticated API routes:
       AuthMiddleware
       → RateLimiter
       → RequestValidation（一次 bounded body read + protocol checks）
       → QuotaMiddleware（仅 P1-06B generative route matrix）
       → endpoint handler Recovery
       → protocol adapter / upstream
```

P1-07A baseline 的 `MaxBytesReader` 对 API 面统一包裹 `r.Body`，但只有后续 handler 读取 body 时才产生可观察错误。P1-07B 将 validation 放在 quota 前，捕获 bounded read overflow，并把一次读取后的 body 放入 context 供 quota/handler 复用。

## 2. 公网入口矩阵（P1-07A baseline）

| Method | Path | Auth | Body/parser | Required fields / model | Max tokens | Stream | Upstream site | Current error shape |
|---|---|---|---|---|---|---|---|---|
| GET | `/health`, `/health/ready`, `/health/live` | no | no body; health uses JSON | none | no | none | none | JSON for health/ready; `OK` for live |
| POST | `/v1/chat/completions` | yes | OpenAI `json.Unmarshal` into `OpenAIChatRequest` | `messages` must be non-empty after adapter; model may be empty and falls back | P1-06B rejects `max_tokens > Client.MaxOutputTokens`; negative passes | request `stream` selects OpenAI stream path | provider adapter | OpenAI-shaped JSON, but validation code is not a shared layer |
| POST | `/chat/completions` | yes | same OpenAI adapter | same | same | same | same | same |
| POST | `/v1/messages` | yes | same OpenAI adapter; no Anthropic-specific schema validation | OpenAI-shaped `messages` required; model may be empty | only `max_tokens` is parsed | same | provider adapter | same OpenAI-shaped JSON |
| POST | `/v1/messages/count_tokens` | yes | `json.Decoder` into `{prompt string}`; decode errors ignored | none | returns `len(prompt)/4` | no | none | HTTP 200 with `tokens`, including malformed/trailing input |
| POST | `/v1/models/{model}:generateContent` | yes | body read; no JSON validation before forward; `capOutputTokens` reparses valid JSON | path model may be accepted/fallback by handler | `generationConfig.maxOutputTokens` is rewritten down to client cap | no | `GeminiService.ForwardRequest` | handler-specific `http.Error` / upstream response |
| POST | `/v1beta/models/{model}:generateContent` | yes | same Gemini proxy | same | same | no | same | same |
| POST | `/v1/models/{model}:streamGenerateContent` | yes | body read; no request JSON validation; response uses bounded SSE parser from P1-06B.1 | path model may be accepted/fallback | request output cap is applied before forward | yes | direct Gemini stream forward | partial handler/upstream response |
| POST | `/v1beta/models/{model}:streamGenerateContent` | yes | same Gemini stream proxy | same | same | yes | same | same |
| GET | `/v1/models`, `/v1beta/models` | yes | no body | none | n/a | no | none; returns configured models | JSON |
| GET | `/v1/models/{model}`, `/v1beta/models/{model}` | yes | no body | no model validation beyond route matching | n/a | no | none; returns model-shaped JSON | JSON |

`/v1/messages` is currently a route alias into `ChatCompletions`, not a separately validated Anthropic adapter. `/v1/messages/count_tokens` is deliberately outside P1-06B generative quota classification and has no upstream call site.

## 3. Body size, media type and encoding（P1-07A baseline）

| Probe | Current result | Evidence |
|---|---|---|
| Hard body cap | `10 << 20` bytes = 10 MiB binary; `MaxBytesReader` returns a `*http.MaxBytesError` after the cap | `internal/middleware/security.go`, `TestP107A_MaxRequestSizeCurrentHardCap` |
| Known `Content-Length` | capped when the handler reads body | characterization test |
| Chunked / `ContentLength=-1` | also capped when the handler reads body; no wrapper-level bypass observed | characterization test |
| Public oversized generative request | P1-07A baseline: quota middleware read first and mapped the error to `QUOTA_CONFIGURATION_INVALID`/HTTP 500; P1-07B regression now asserts the corrected 413 path | PR #20 baseline + `TestP107B_PublicOversizedGenerativeBodyStable413` |
| `Content-Type` | not checked; valid JSON with `text/plain` reaches OpenAI/Gemini handler and upstream | handler characterization tests |
| `Content-Encoding: gzip` | not decompressed and not explicitly rejected; OpenAI JSON parser sees compressed bytes and returns generic HTTP 400 before upstream | `TestP107A_GzipRequestIsNotDecompressed` |

P1-07B target: stable `REQUEST_TOO_LARGE`/413, explicit supported JSON media types, and explicit rejection of unsupported compression before business parsing.

## 4. JSON structure and protocol behavior（P1-07A baseline）

### OpenAI-compatible handler

| Input | Current behavior | Upstream call |
|---|---|---:|
| malformed JSON | 400 `invalid_request_error`, bounded generic message | 0 |
| trailing second JSON value | 400 because `json.Unmarshal` rejects the whole input | 0 |
| top-level array/string | 400 unmarshal error | 0 |
| top-level `null` | unmarshal succeeds to zero struct, then empty messages gives 400 | 0 |
| wrong `messages` type | 400 unmarshal error | 0 |
| empty messages | 400 `No content in messages` | 0 |
| unknown extension field | accepted; default decoder ignores unknown fields | 1 |
| duplicate field | accepted; standard unmarshal last value wins | 1 when final value is valid |
| empty model | accepted; provider/default model fallback path is used | 1 |
| model control character | no model validation; escaped control character reaches provider path | 1 |
| deeply nested unknown value (depth 100) | accepted; no explicit depth limit | 1 |
| 5,000-message array within body cap | accepted; no message-count bound | 1 |
| negative `max_tokens` | accepted by handler; no non-negative integer validation | 1 |
| very large `max_tokens` | rejected by existing P1-06B client output cap as `MAX_OUTPUT_TOKENS_EXCEEDED` | 0 |

The current OpenAI error response is JSON-shaped with `message`, `type` and `code: null`, plus the server request ID when the RequestID middleware is present. It has no P1-07 stable validation code taxonomy.

### Gemini proxy handler

- `GenerateContent` and `StreamGenerateContent` enforce the existing P1-06B conservative byte-based `MaxInputTokens` check, but do not parse or validate request JSON before the upstream call.
- Valid JSON with the wrong `Content-Type` reaches upstream in the direct handler path (subject only to the existing output-cap rewrite).
- Malformed JSON also reaches upstream; `capOutputTokens` returns the original body when its reparsing fails.
- `generationConfig.maxOutputTokens` is rewritten down to `Client.MaxOutputTokens`; it is not rejected as a protocol validation error.
- Streaming response usage is already handled by P1-06B.1's bounded SSE parser; this characterization focuses on inbound request validation, not that completed-response accounting contract.

### `count_tokens`

`POST /v1/messages/count_tokens` uses a decoder without checking decode errors or a second JSON value and returns `len(prompt)/4`. It does not call an upstream provider and remains excluded from P1-06B generative quota preflight.

## 5. Invalid-input upstream boundary（P1-07A baseline）

The OpenAI tests use a local HTTP canary and show malformed/trailing/top-level/type/empty-message inputs stop before that canary. The Gemini tests show the opposite current boundary for malformed JSON and wrong media type: the request is forwarded. The public route registration test confirms every listed route exists behind the auth middleware; the body-limit test confirms the public generative oversized path currently fails in quota preflight before upstream.

No request body, prompt, authorization value or provider key is echoed by the OpenAI validation errors covered here. Gemini's current malformed-input behavior is an upstream-forwarding gap, not a body-echo claim.

## 6. KNOWN-GAP：P1-07A baseline candidates

1. No shared request-validation layer exists across OpenAI-compatible, `/v1/messages`, Gemini native and streaming adapters.
2. Oversized public generative bodies do not have the target stable `413 REQUEST_TOO_LARGE` contract; current quota preflight can surface 500.
3. Content-Type is not allowlisted and unsupported request compression is not explicitly rejected.
4. JSON trailing values, top-level object shape, maximum nesting depth, duplicate-field policy and protocol-specific scalar/array types are not expressed consistently. OpenAI happens to reject some malformed shapes through `json.Unmarshal`; Gemini does not.
5. Model is not uniformly required, bounded, UTF-8/control-character checked, or validated per protocol.
6. Negative/overflow/unknown max-token fields do not have a shared numeric contract; existing P1-06B output-cap behavior is only a partial check.
7. Message/contents array size and nested extension depth have no explicit bounds besides the body cap.
8. Every invalid-input case lacks a public-router canary matrix asserting `upstream_call_count == 0`; current tests cover representative OpenAI zero-call and Gemini forwarding behavior.
9. Validation errors do not yet share a stable cross-protocol code schema, and request-body read errors are handler/quota-layer specific.

## 7. TARGET：P1-07B boundary（implemented in current branch）

P1-07B may introduce a shared bounded body/JSON safety layer with protocol adapters. It should preserve unknown extensions for compatibility while enforcing:

- 10 MiB hard cap for both Content-Length and chunked bodies with stable 413 `REQUEST_TOO_LARGE`;
- explicit JSON media type and unsupported-compression policy;
- malformed JSON, trailing values, non-object top-level values and bounded nesting rejection;
- minimum per-protocol validation for model, messages/contents, stream and max-token fields;
- broad model compatibility (`/`, `-`, `_`, `:`, `.`) without accepting control characters or unbounded values;
- upstream canary proof that every invalid case makes zero provider calls;
- bounded, non-echoing validation errors with RequestID preserved;
- continued P1-04 privacy, P1-05 lifecycle and P1-06 rate/quota regressions.

P1-07A did not implement this target.

## 8. P1-07B Enforcement Results

- Pipeline order is now `Auth → Rate Limit → Request Validation → Daily Quota → Handler → Upstream`.
- `RequestValidation` performs one bounded read for registered public POST body routes, stores the body in request context, and maps both known-length and chunked overflow to 413 `REQUEST_TOO_LARGE`.
- `Content-Type` accepts `application/json` with parameters and rejects other media types with 415 `UNSUPPORTED_MEDIA_TYPE`; non-identity `Content-Encoding` is rejected with 415 `UNSUPPORTED_CONTENT_ENCODING`.
- Shared JSON checks reject invalid UTF-8, malformed/trailing values, non-object top-level values, and nesting beyond 64. Unknown extension fields remain accepted; model, collection and declared output-token bounds are enforced without `DisallowUnknownFields`.
- The conservative byte-based `MaxInputTokens` bound is checked before Daily Quota reservation; handler-level checks remain as a direct-call defense in depth.
- OpenAI-compatible, `/v1/messages`, Gemini native and Gemini streaming paths now enforce protocol minimums before quota reservation. Invalid cases return bounded stable JSON errors and local public-router canaries observe zero upstream calls.
- Quota and handlers consume the validator's context body rather than independently reading the inbound stream. `/v1/messages/count_tokens` remains non-generative but now gets the shared bounded JSON/media validation.
- Valid unknown extensions and valid streaming requests remain accepted; RequestID is preserved on validation errors and successful responses.

P1-07B closes the P1-07A validation gaps. More detailed rationale and bounds are recorded in [ADR-009](adr/ADR-009-request-validation-boundary.md).

## 9. Evidence

- P1-07A baseline tests: `internal/middleware/p1_07a_request_validation_characterization_test.go`, `internal/handlers/p1_07a_request_validation_characterization_test.go`, `cmd/server/p1_07a_public_route_characterization_test.go`
- P1-07B tests: `internal/middleware/p1_07b_request_validation_test.go`, `cmd/server/p1_07b_request_validation_gate_test.go`
- Design record: `docs/adr/ADR-009-request-validation-boundary.md`
- P1-07A targeted command: `go test ./internal/middleware ./internal/handlers ./cmd/server -run 'TestP107A_' -count=1 -v`
- P1-07B targeted command: `go test ./internal/middleware ./internal/handlers ./cmd/server -run 'TestP107B_' -count=1 -v`
- Final gate: `bash scripts/verify.sh`

P1-07A conclusion: baseline behavior and gaps were characterized. P1-07B conclusion: the shared request-validation boundary is implemented and covered by regression/zero-upstream tests.
