// Package httpsignature implements RFC 9421 HTTP Message Signatures and RFC
// 9530 digest fields for net/http using the pinned RFC 8941 Structured Fields
// dialect, not later dialect extensions. Start with explicit SigningProfile
// or VerificationProfile and parser limits; optional digest/body/HTTP adapters
// compose these without owning a server, client, key store or business effect.
// Compatibility isolates caller-implemented legacy protocols. No cgo is added.
//
// Parsing and cryptographic validity do not authenticate or authorize an
// operation by themselves. Applications must construct explicit signing and
// verification profiles, resolve algorithm-bound keys, enforce replay policy,
// supply trusted external request context behind proxies, and map safe typed
// failures to their own protocol. Profiles copy policy collections but borrow
// clocks, providers, resolvers, replay stores and cryptographic key objects.
// Concurrent use requires safe immutable collaborators and message snapshots;
// bound callbacks and I/O cooperatively with context. No callback/crypto worker
// is detached to force cancellation. Buffered versus streaming body ownership
// is explicit; transport/body cleanup and authentication policy are not global
// defaults. Editions/local choices are in docs/specification-decisions.md;
// these comments do not qualify the pinned conformance or external corpora.
package httpsignature
