# Security threat model: go-http-signature

**Model version:** 1.0 (2026-09-22)

**Source baseline:** `c62671a7a92e281d2186a10855b129d9b1145613` on `main`

**Scope:** root Go module, including `compatibility`; source-level assessment,
not a deployment certification or release approval.

This model describes the library boundary at the stated source baseline. The
application supplies the signing and verification profiles, trusted keys,
replay implementation, HTTP topology, and authorization decision. See the
[security policy](../SECURITY.md), [profile guidance](security.md),
[hardening review](security-review.md), and [integration ordering](integration.md)
for the corresponding operational contracts. Revisit this model when any of
those contracts or the implementation changes.

## Assets and attacker control

| Asset or property | Attacker-controlled input or action |
| --- | --- |
| Signing keys and resolved verification material | Key identifiers, signature parameters, and requests that trigger caller-owned key resolution; possible access to application logs or diagnostic callbacks. |
| Integrity of selected HTTP method, target, headers, trailers, and content | Wire messages, field-line combinations, encodings, query syntax, body bytes, and transport/proxy transformations. |
| Freshness and single use of protected operations | Captured signed messages, timestamps, nonces, concurrent retries, and replay-backend failures. |
| Availability and bounded resource use | Oversized or malformed Structured Fields, bodies, resolver traffic, replay-store capacity pressure, and stalled callbacks/backends. |
| Authorization and tenant isolation | A valid signature made with a key that is not entitled to the requested operation or tenant. |

The attacker may control unauthenticated inbound HTTP and may replay observed
traffic. They do not control the application's configured profile, trusted
clock, key store, trusted proxy context, or replay backend unless one of those
separate boundaries is compromised. Caller-supplied signing inputs and legacy
adapter implementations are treated as potentially faulty, not as an
independent guarantee from this module.

## Trust boundaries and controls

| Boundary | Existing module control | Required application or deployment control |
| --- | --- | --- |
| Wire fields to parsed signature and digest structures | Explicit syntax limits; strict field-specific parsing and duplicate/label checks; narrow panic containment around the external Structured Fields parser (`syntax_limits.go`, `signature_fields.go`, `structured_field_safe.go`, `digest.go`). | Set ingress/header and body limits before the library; reject unsupported authentication formats instead of silently translating them. |
| Parsed signature to policy and cryptographic proof | Immutable validated `VerificationProfile`; explicit label and required-component checks; time and algorithm policy; bounded resolver call; exact resolved-key algorithm, validity, freshness, and revocation checks; standard-library cryptography (`verifier.go`, `algorithm.go`). | Choose complete covered semantics, active algorithms, key types, clock/skew, rotation, revocation freshness, and bounded resolver behavior. Do not treat `VerifiedSignature` as authorization. |
| HTTP representation to signature base | Deterministic `net/http` component derivation and rejection of ambiguous transformations; trusted `ExternalRequestContext` is required when configured; forwarded headers are not trusted automatically (`message.go`, `http_integration.go`, `body_integration.go`). | Reconstruct external origin only at a trusted proxy boundary and test the deployed proxy/HTTP-version path. Authenticate digest values **and** relevant representation metadata; verify the body before processing it. |
| Verified signature to replay decision | Nonce consumption occurs after cryptographic verification; bounded, process-local `MemoryReplayStore` is atomic within one process and fails on capacity; verifier rejection covers uncertain caller-owned replay backends (`verifier.go`, `replay.go`). | Require nonce/freshness policy appropriate to the operation. Use an atomic durable `(keyid, nonce)` store across instances; do not retry a protected side effect after an unknown commit. |
| Signing or verification to HTTP emission and application handler | Buffered adapters bound body size; streaming/trailer adapters reject unsupported or incomplete states; protected fields and transport-owned framing have explicit handling (`http_integration.go`, `body_integration.go`). | Order digest, signature, authentication, and authorization explicitly. Do not consume content or act on partially emitted streaming output before authentication completes. Recreate requests for each retry. |
| Library errors to observability | Verification and signing errors expose coarse categories without rendering key IDs, nonces, bases, signatures, or bodies (`verifier.go`, `signer.go`). | Redact resolver/replay diagnostics and application logs. The `compatibility` diagnostic callback receives original external errors and must be separately redacted (`compatibility/adapter.go`). |

The `compatibility` package does not implement or parse Cavage, AWS SigV4,
OAuth 1.0, or vendor signatures. It isolates caller-supplied implementations
from RFC 9421 fields; the external implementation's security properties remain
outside this model.

## Accepted residual risks and review triggers

These are **conditional module-scope acceptances**, not acceptance of any
deployment configuration. The named owner must decide whether the mitigation
is sufficient for its deployment.

| Residual risk | Owner and rationale | Mitigation and condition for review |
| --- | --- | --- |
| A valid signature may omit a security-relevant method, target, digest, or representation field, or belong to a signer without authority. | Application protocol and authorization owner; no universal HTTP coverage or grant semantics can safely be selected by this library. | Define and test a complete profile and perform separate tenant/capability authorization. Review on route, proxy, payload, or authorization-policy changes. |
| Process-local replay state cannot stop cross-instance replay; timeout or unknown commit cannot prove whether a nonce was consumed. | Deployment and replay-backend owner; distributed atomicity and side-effect coordination require external infrastructure. | Use durable atomic consume, bounded TTL, fail-closed uncertainty, and idempotency for retries. Review on scaling, failover, backend, or retry changes. |
| Proxy canonicalization, trailer loss, content coding, and response bytes already emitted can differ from the library's authenticated model. | HTTP integration owner; intermediaries and committed bytes are outside the library's control. | Test actual transport/proxy transformations; reject incomplete trailers and late signing failures; require client-side complete-content verification. Review on proxy, HTTP-version, middleware-order, or streaming changes. |
| Keys may persist in Go-managed memory and caller-owned resolvers or diagnostic callbacks may disclose sensitive data. | Key-management and observability owner; Go offers no reliable key zeroization and callbacks are application code. | Restrict key lifetime and access, keep dumps/logs redacted, bound and audit resolver freshness, and redact compatibility diagnostics. Review on key-store, telemetry, or incident tooling changes. |
| Strict parser and body bounds can reject otherwise valid large messages or be exhausted by hostile traffic before library entry. | Edge/operations owner; finite limits trade interoperability for bounded work and do not replace upstream admission controls. | Configure measured limits, ingress controls, and safe failure mapping. Review on traffic-size, dependency-parser, or limit-policy changes. |
| Legacy compatibility callbacks carry the full security semantics of their external protocol. | Application adapter owner; this module neither validates nor upgrades those schemes. | Independently review and test each supplied implementation and keep its wire fields separate from RFC 9421. Review on adapter or external dependency changes. |

## Per-module release verdict

**Root module (`github.com/faustbrian/go-http-signature`, including
`compatibility`): not approved for a new release by this document.** The source
contains explicit controls for the boundaries above, and the remaining risks
have identified owners and review conditions, but this documentation-only
assessment did not execute tests, vulnerability or secret scanners, CI,
consumer checks, or a release rehearsal. Before any release decision, bind
the candidate commit and dependency set; run the risk-selected repository and
release gates; review their actual results and current advisories; and confirm
that application-facing profile and integration caveats remain accurate. The
published stable-v1 support policy is separate from unreleased `main` source.
