# Source documentation audit

## Scope, contract and missing context

This Tier A prose pass owns baseline
`119c3518ca0117de89adf6f2601deeee65077aef`. Reproduce the tracked inventory
with `git ls-files '*.go' '*go.mod'` and `golib source-docs inventory --json`:
56 Go files (15 maintained source, 40 tests and one clean-consumer fixture),
three modules and two public production packages. The comparison and
shared-corpus modules are non-releasable test-only harnesses, not extra public
libraries. There are no generated/vendor, platform or build-tag Go variants.
Nine root fuzz targets, three root benchmarks plus one comparison benchmark,
two root examples and both existing TestMain cleanup owners are in scope.
The baseline has 162 objective public declaration/member comment gaps.

| Owner | Audited contract and rationale |
| --- | --- |
| Protocol fields/digests | RFC 8941 dialect containment under the pinned supplier, complete ordered field combination, duplicate-label refusal, preserved extensions, defensive copies and before/after-parser resource bounds. |
| Message/base | RFC 9421 component identity versus serialization order, explicit related/proxy context, managed net/http field representation, bounded intermediates, HTML-form query decoding and ambiguity refusal. |
| Algorithm/profile | Registered local algorithm/key constraints, borrowed immutable asymmetric keys versus copied HMAC, explicit metadata policies, cooperative provider/resolver deadlines, distinct signing/key freshness windows and safe error boundaries. |
| Replay/verifier | Explicit label-set/coverage selection, crypto before nonce consumption, key/nonce identity, accepted-skew retention, unknown outcomes and business-effect separation, heap/cancellation/clock ownership. |
| HTTP/body adapters | Header/trailer snapshots, borrowed original callbacks versus metadata-only views, eager body closure/replacement, streaming EOF finality and partial wire output, transport error passthrough, response protocol bypass refusal and reporting ownership. |
| Compatibility | Separate caller-implemented legacy protocols, isolated callback views, protected RFC fields retained, delegated body ownership and raw diagnostic reporter trust. |
| Tests/harnesses | File-level boundary assertions, controlled body/writer/clock/lifecycle fixtures, exact RFC/corpus inputs, local versus peer behavior, fixture cleanup and equivalent benchmark workloads. |

Acceptance is truthful useful rendered documentation with unchanged executable
AST/tokens/literals, directives, example outputs, dependency/API bytes and
historical authority/review evidence. Checks select formatting, all-tracked
structure preservation, native docs/examples/README compilation, local links,
changed-content secrets and one ordinary complete final-diff inspection.
No unchanged crypto, service, active fuzz, race, external corpus, performance
or release campaign is selected. Test-only harnesses are audited without
requalifying their unchanged external peers.

## Corrected current record and generation boundary

Current `HTTP-SIG-DEC-006` incorrectly described Go form parsing, retained
repeated values, malformed-escape refusal and multiple base lines. Actual
`queryParameter` uses the maintained HTML-form decoder, preserves malformed
escapes literally, replaces invalid UTF-8 and requires exactly one matching
decoded requested name. Existing tests protect those outcomes. Correct the
current JSON/human mirror and append its native typed digest while preserving
all previous history and frozen pins; no decoder change is included.

Other corrected prose distinguishes core-created versus arbitrary public
failure strings and upstream transport errors from adapter-owned body closure.
The canonical package entry is `doc.go`, not a competing shorter digest entry.
Relevant authority editions are [the current decisions](specification-decisions.md)
and [pinned RFC/registry inputs](../spec/sources.lock.json). Parser corrections
retain RFC 8941 policy rather than automatically adopting later SF dialects.

Native API mode is `apidiff` export data at `api/baseline.txt`, not full Go-doc
prose. Preserve the export snapshot, README compiled snippet, RFC/HTTPWG/shared
corpora, source locks, peer versions and cryptographic fixtures. No tracked Go
source claims generation. Corpus/source update commands belong to existing
scripts and harness notes; none is executed by this pass.

No unsupported conformance, security review refresh, consumer migration or
release claim is inferred. The coordinator owns shared CI enforcement and
remote-main qualification. Prose does not require a release or repin.
