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

Full scheduled and release mutation gates must finish with zero surviving viable
mutants. Local mutation is optional, not a universal contribution prerequisite.

Do not add package-local workflows, permanent replacements, machine-specific
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

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.
