# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected module's docs.
2. Run standalone Go tests in the affected module.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Repository verification is provided by the released `go-library-tools` version
and checksum in `.golib.yaml`. The Makefile is a thin local entry point;
package-specific verification remains in `verification/package.mk`, while the
API baseline and mutation checkpoints remain repository-owned.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected [stable decision entries](docs/specification-decisions.md), and complete the Specification Decisions
section of the pull request template. An unresolved interpretation or stale
source pin is release-blocking; peer behavior cannot silently select policy.

Selected full mutation qualification must finish with zero surviving viable
mutants. Local mutation is optional, not a universal contribution prerequisite.

Do not fork shared verification workflows, add permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

## Verification

Use Go 1.27.2 for development and CI; module minima remain Go 1.27.0. Root
tests need no sibling checkout or ecosystem ledger:

```bash
GOWORK=off go test ./...
```

Ordinary tests run deterministic fuzz seeds and saved corpus regressions, not
active exploration. The owned comparison and shared-corpus modules remain
separate non-releasable public-dependency harnesses. No module declares services
or test/build tags. External corpus qualification still requires its pinned
inputs; an ordinary test pass does not prove fetched source identity.

With the checksum-pinned public verifier selected by `.golib.yaml`, use:

```bash
make inventory
make check
make ci
```

Both Make routes use bounded local checks. Base-free checks run seeds/corpora;
changed-source CI selects bounded active smoke for causally affected targets.
Ordinary CI consumes the public verifier without building it from source. One
root race command selects atomic replay consumption (exactly one winner among
32 joined contenders) and shutdown cancellation stopping both resolver and
replay callbacks with typed failures. It runs once with a two-minute timeout.

Short active exploration selects one target; optional local mutation selects
one package:

```bash
GOMAXPROCS=2 GOWORK=off go test -run '^$' -fuzz '^FuzzParseSignatureInputs$' -fuzztime=2s -parallel=1 -timeout=2m .
golib mutation --module . --package .
```

`make specification-check` validates the register offline;
`make specification-check-online` explicitly refreshes reviewed source digests.
`make check-full` retains online validation, all nine native 10000x fuzz budgets,
supplemental replay race/count100, deterministic sign/expiry count1000,
verifier lifecycle race/count20, fault refusals, clean consumer, normative source
and corpus checks, interoperability and sampled comparison benchmarks.
Signature/base/digest/parser, body/transport, cryptographic, replay, resolver and
redaction changes retain their affected refusal and conformance assertions.
Public API changes retain compatibility and directly affected public consumers.
Relevant release qualification remains `golib release dry-run --module .`.
Report unavailable, skipped and failed boundaries honestly; local tests are not
full corpus, hosted-CI or public-release qualification.

## Selected Scheduled Assurance

The separate [selected-assurance caller](.github/workflows/assurance.yml) runs
only on main, every Sunday at 04:11 UTC. It rotates one current declared root
fuzz target for 30 seconds, exploring:
signature/digest field parsing and canonicalization, multiline equivalence,
trusted trailer context and raw HTTP message boundaries.
The nine declared root targets are in-process syntax/message checks, not
cryptographic certification, replay lifecycle qualification or a fetched
external-corpus proof. The comparison and shared-corpus modules remain separate.

Base-free ordinary checks execute deterministic seeds, not active exploration;
committed-range CI selects affected active smoke. Manual assurance requires an
exact anchored selector from the root fuzz operation in `.golib.yaml`, for
example `^FuzzStrictStructuredFieldsMultiline$`.
Empty, unknown and malformed selections refuse.
The shared job bounds setup and execution to ten minutes, active workers and
CPU to two, owned memory to 2 GiB, native output to 1 MiB and private-cache
lifetime. Failure, cancellation, exhausted budgets and cleanup refusal remain
attributable failures. This lane does not run mutation or replace Required,
explicit `make check-full`, or relevant release qualification.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.

## Source Documentation

Install the checksum-pinned public verifier declared in `.golib.yaml`.
`make source-docs-check` validates objective Go comment, marker, link and
generated-producer structure; `make check`, `make check-full` and `make ci`
require it before their existing checks. Shared CI runs the same strict
contract and includes its result in Required. This is structural enforcement,
not a substitute for source-truth review or behavioral verification.
