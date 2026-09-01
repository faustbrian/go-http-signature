# Changelog

All notable changes to this module are documented in this file.

Observable protocol changes are governed by the
[specification decision register](docs/specification-decisions.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation

- Replace the archived monorepo link with package-owned documentation.

### Changed

- Adopt the checksum-verified `go-library-tools` v1.2.0 CLI and immutable
  shared workflow so local and hosted gates enforce specification governance
  while retaining RFC conformance, interoperability, lifecycle, and
  clean-consumer contracts.
- Refresh reviewed RFC Editor errata and IANA field-registry source identities
  after rendering and unrelated registration changes left this package's
  complete errata inventory, selected fields, and decisions unchanged.

Decision records: HTTP-SIG-DEC-001 sha256:0bc50d4da96a7f7ce5b544858f4537558c3bece6da0bee0c603604ada26cab9d,
HTTP-SIG-DEC-002 sha256:cd6d15ddbd043a128a8e95e44754c12e652e492c0de551813a8c688d017c1b79,
HTTP-SIG-DEC-003 sha256:edc1e3d2f87fd383a6d556ce93b8a870352664c3fb5befb0e7f7dc8d143fdb23,
HTTP-SIG-DEC-004 sha256:f9bacc838674338a9924718cddd93eb1c06743be3bcffb953cf93ef142f21eb7,
HTTP-SIG-DEC-005 sha256:bcd8ca5c880aa9662711fe41306b655110f30e787066de39eaa46ec308e0bf2f,
HTTP-SIG-DEC-006 sha256:c40a2f08e8f95671a820c3e1f8e6b50731c426ef4dd821965876f2b1c0982417,
HTTP-SIG-DEC-007 sha256:101e15ea4c3ca45d73ed71197da30c4c1f8167efed14d596a9cabc339ceb8279,
HTTP-SIG-DEC-008 sha256:0d5fc9657f0ab466b613cd1aa96c75aef0c6f64efcfcdf31a0b079e56016f7a3,
HTTP-SIG-DEC-009 sha256:6ac49d7cc3b53f65ea9fffe9fe0392f840315a1d43220f7a297df7e7a97c4f26,
HTTP-SIG-DEC-010 sha256:f064e4a01b7a8e565b78bbbf62eba7e8513804e9f949f5e211cc2623acc8a1cf,
HTTP-SIG-DEC-011 sha256:adf6192f94956dd59206aff2cb1f9f2787e248ac8b20e4a5dd66b5f96326f1c0,
HTTP-SIG-DEC-012 sha256:1023598bf6f09889f12e47f980998be35df5b41e0da9b93981178877371bc284,
HTTP-SIG-DEC-013 sha256:273420c4fa0e24b8cd58ea42a0a3c98f3895a78252af7958ae5647ffa0c4ecc4,
HTTP-SIG-DEC-014 sha256:88c3e3a074f25b7c9142fe98036f57ceb183d5af138964e06230d1b434c20b44,
HTTP-SIG-DEC-015 sha256:75383d941b245fe8d4b814a5247dcacbc8841b0cd54f5b68a89929f5ac728ed7,
HTTP-SIG-DEC-016 sha256:fc1909dd5c755ec30967a75b3b3d67e6d6eb27ef64cc86982c142c1b0aeb7a1b,
HTTP-SIG-DEC-017 sha256:5872897bae6f55add35c2787da75aef5b8e6d1a1628ef803865e46950cb3c701,
HTTP-SIG-DEC-018 sha256:765f9f475c703cec3dcf22365e29b193074c36e61c56f18da2bc8645bc06abcc,
HTTP-SIG-DEC-019 sha256:486b92b36fd9851cffa5b093392f832672b6f80b82dc139901e7b2ec61acfb5d,
HTTP-SIG-DEC-020 sha256:c763717912707df0f61f79f19c7ba4a464ff72ea4311a391c6521a84e8b81f47 .


### Fixed

- Reconcile nested benchmark and differential harnesses with the canonical
  `v1.0.0` module archive so isolated module checks remain reproducible.

## [1.0.0] - 2026-08-25

### Fixed

- Invoke comparison benchmarks directly from their owning module and resolve
  its stable root-module requirement from the current standalone source.

### Changed

- Upgrade cryptography dependencies in comparison and differential modules to
  the current security-fixed release.

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Fixed

- Prove escaped quoted-string scanning before repairing a following integral
  RFC 8941 Decimal, killing the previously surviving conditional mutant.

### Documentation

- Link the package README to package-owned documentation.

### Added

- Add an auditable RFC 8941, RFC 9421, and RFC 9530 specification decision
  register with explicit compatibility and security consequences.
- Add isolated equivalent request sign-and-verify benchmarks against pinned
  `yaronf/httpsign` and `dadrus/httpsig`, with separate correctness proof,
  repeated samples, environment capture, and documented policy-cost
  differences.
- Convert Structured Fields dependency panics on hostile extension syntax into
  typed parse failures across signature, digest, and canonicalization entry
  points.
- Combine multiple Structured Field lines with the RFC-mandated comma and space
  before parsing, reject leading horizontal tabs outside RFC 8941
  optional-whitespace positions, and retain the required fractional zero when
  canonicalizing integral Decimal values.
- Add isolated compatibility `RoundTripper` and verification middleware seams
  for Cavage drafts, AWS SigV4, OAuth 1.0, and explicitly named vendor schemes;
  outbound callbacks cannot replace request identity or RFC 9421 signature
  fields, and inbound callback mutations cannot reach later RFC verification.
- Add streaming response digest/signature trailers with canonical application
  declarations, bounded authenticated late-trailer support, fail-closed
  protocol constraints, and client-side verification that waits for EOF before
  releasing response content.
- Make buffered response signing inherit outer ordinary headers with normal
  handler replacement semantics and reject handler-managed transfer or trailer
  framing, protocol switching, and successful `CONNECT` before signing.
- Fail streaming adapters on zero-progress body readers and reject protocol
  switching where digest/signature trailers cannot complete.
- Preserve application trailer values populated at EOF across buffered request
  digest generation and verification without losing caller-declared framing.
- Prevent streaming request downgrade by forcing supported HTTP/1 attempts to
  chunk even empty bodies, preserving and authenticating only predeclared EOF
  trailers, rejecting early responses and `CONNECT`, and refusing profiles that
  cover transport-dependent connection or framing fields.
- Clear handler-injected protected response trailers on every late streaming
  failure, omit mutable TLS state from verification callback snapshots, and
  report signed buffered-response short, invalid, or failed writes once through
  a redacted late diagnostic path.
- Add deterministic RFC 9530 SHA-256 and SHA-512 integrity-field generation,
  strict byte-sequence parsing, immutable ordered values, and policy-selected
  constant-time verification.
- Add ordered RFC 9530 integrity-preference parsing and serialization with
  strict integer weights, duplicate rejection, and unknown-algorithm retention.
- Add explicit and default-bounded parser resource limits across signature,
  digest, and negotiation fields.
- Bound complete signature-base canonicalization by default and permit a
  stricter per-message ceiling.
- Bind transport-owned Host, content-length, transfer-encoding, trailer, and
  connection components to deterministic `net/http` wire state, including
  method- and status-sensitive zero-length request and response emission,
  exact transfer-coding spelling and order, and response body-probe ambiguity,
  with an explicit received-versus-`Response.Write` transport mode that rejects
  ambiguous zero-value contexts, unavailable inbound trailer identity, and
  stale outbound header aliases.
- Reject noncanonical or multi-line Cookie coverage and require binary wrapping
  for multiple Set-Cookie field lines to prevent transformation collisions.
- Add strict ordered parsing for `Signature-Input` and `Signature`, rejecting
  duplicate labels, wrong Structured Fields member types, duplicate covered
  component identifiers, and RFC 9651-only values outside RFC 8941.
- Preserve RFC 8941 Item parameters on `Signature`, `Content-Digest`, and
  `Repr-Digest` members instead of rejecting legal extensions.
- Add ordered `Accept-Signature` parsing and serialization with distinct
  Boolean creation and expiration request semantics.
- Add request signature-base construction for registered derived components,
  header and trailer selection, field combination, explicit external request
  context, request-response component binding, and Structured Fields modes.
- Add all active IANA signature algorithms with exact RFC encodings, strict key
  compatibility, Go-managed cryptographically secure RSA-PSS and ECDSA
  randomness, cancellation, and secret-safe typed verification failures;
  retain the former caller-random inputs as ignored compatibility parameters so
  weak or blocking readers cannot affect signing.
- Add explicit verification profiles with mandatory coverage, parameter,
  algorithm, time, tag, key-resolution, cache-freshness, and nonce policy.
- Reject zero-length verification-key validity windows even when configured
  clock skew would otherwise make the instant appear acceptable.
- Add explicit signing profiles and context-bounded rotating-key providers that
  create deterministic matching field pairs without mutating messages or
  consuming bodies.
- Add profile-level mandatory trusted external request context that fails
  before signing-provider or verification-resolver access.
- Reject trusted external-origin contexts whose scheme or authority
  contradicts an absolute-form request target.
- Preserve double-slash origin-form paths and reject request-target fragments,
  user information, opaque targets, and absolute targets without authority.
- Reconstruct authority-form and asterisk-form target URIs with an empty
  path/query while retaining the normalized `/` value for `@path`, and reject
  special forms used with the wrong method.
- Normalize authority ports numerically so leading-zero default ports are
  omitted and other ports have a stable decimal representation.
- Reject authority values containing query, fragment, or opaque URI data.
- Add explicit outbound signing round-tripper and inbound verification
  middleware adapters with caller-owned label selection, trusted external
  request context, failure mapping, existing-field policy, and body ownership.
- Add bounded fail-closed response-signing middleware and a response-verifying
  round-tripper with request-response binding, authenticated digest coverage,
  callback isolation, transparent-decompression rejection, and replayable
  verified bodies; buffered digest and trailer paths reject 101 and successful
  `CONNECT` before reading opaque protocol or tunnel bytes.
- Match body suppression for `HEAD`, 204, 205, and 304 when signing responses,
  including rejecting RFC-forbidden 205 handler content and digesting only
  content actually emitted.
- Add explicit bounded Content-Digest round-tripper and verification
  middleware with caller-body closure, replayable clones, and no partial
  delegation after size or digest failure.
- Add a bounded streaming request adapter that computes Content-Digest while
  the transport reads, then signs the declared digest trailer at EOF without
  falsely advertising replayability.
- Add eager inbound trailer verification that waits for EOF, checks the
  bounded content digest, authenticates a profile-required trailer component,
  and only then delegates a replayable body.
- Fail buffered body processing closed when releasing caller-owned body
  resources fails, without exposing the underlying close error.
- Add an atomic bounded process-local replay store and a context-aware durable
  replay adapter contract with fail-closed capacity and backend semantics.
- Pin the RFC texts, errata records, and relevant IANA registries with explicit
  decisions for every currently listed erratum.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-http-signature` identity while preserving its documented API and behavior.
- **Breaking:** `ResponseSigningMiddlewareConfig.ReportError` is now required.
  Callers must provide a concurrency-safe callback that records redacted late
  output failures; `MapError` remains responsible only for failures that can be
  mapped before response commitment.

[Unreleased]: https://github.com/faustbrian/go-http-signature/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/faustbrian/go-http-signature/releases/tag/v1.0.0
