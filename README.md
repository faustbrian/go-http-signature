# http-signature

[![CI](https://github.com/faustbrian/go-http-signature/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/faustbrian/go-http-signature/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-required-blue)](https://github.com/faustbrian/go-http-signature/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Mutation](https://img.shields.io/badge/mutation-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Documentation](https://img.shields.io/badge/docs-checked_in_CI-blue)](docs/)
[![Go Reference](https://pkg.go.dev/badge/github.com/faustbrian/go-http-signature.svg)](https://pkg.go.dev/github.com/faustbrian/go-http-signature)
[![Release](https://img.shields.io/github/v/release/faustbrian/go-http-signature?sort=semver)](https://github.com/faustbrian/go-http-signature/releases)
[![Go](https://img.shields.io/badge/go-1.26.6-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`http-signature` implements HTTP Message Signatures (RFC 9421) and HTTP digest
fields (RFC 9530) for Go `net/http` messages. The core separates Structured
Fields syntax, signature-base construction, cryptographic algorithms, signing
and verification policy, key resolution, replay consumption, and HTTP
adapters.

It does not replace TLS, authentication, authorization, or capabilities. A
successful verification proves only cryptographic validity and conformance to
the selected application profile.

## Install

```sh
go get github.com/faustbrian/go-http-signature@v1
```

## Minimal request signing

```go
profile, _ := httpsignature.NewSigningProfile(httpsignature.SigningProfileConfig{
    AllowedAlgorithms: []httpsignature.Algorithm{httpsignature.HMACSHA256},
    CoveredComponents: []httpsignature.ComponentIdentifier{
        {Name: "@method"},
        {Name: "@authority"},
        {Name: "content-digest"},
    },
    Expires: httpsignature.ParameterRequired,
    AlgorithmParameter: httpsignature.ParameterRequired,
    Nonce: httpsignature.ParameterForbidden,
    Tag: httpsignature.ParameterForbidden,
    Lifetime: time.Minute,
    ResolveTimeout: time.Second,
    Now: time.Now,
    Provider: provider,
})

signing, _ := httpsignature.NewSigningRoundTripper(httpsignature.SigningRoundTripperConfig{
    Transport: http.DefaultTransport,
    Signer: httpsignature.NewSigner(profile),
    Label: "sig",
    Existing: httpsignature.ExistingSignaturesReject,
    Options: func(context.Context, *http.Request) (httpsignature.SigningOptions, error) {
        return httpsignature.SigningOptions{}, nil
    },
})

digesting, _ := httpsignature.NewBufferedContentDigestRoundTripper(
    httpsignature.BufferedContentDigestRoundTripperConfig{
        Transport: signing,
        Algorithms: []httpsignature.DigestAlgorithm{httpsignature.SHA256},
        MaxBytes: 1 << 20,
    },
)
client := &http.Client{Transport: digesting}
```

The wrapper order is significant: digest first, signature second, network
transport last. This ensures the signed message already contains the digest.

## Verification model

Create a `VerificationProfile` with explicit allowed algorithms, required
components, time policy, nonce policy, key resolver, resolution timeout, and
optional mandatory external request context. Applications select the signature
label and map typed failures to HTTP responses. Verification metadata stored in
context is not an authorization decision.

Behind a proxy, set `RequireExternalRequestContext` and supply a trusted
`ExternalRequestContext` from deployment configuration. The package never
reads `Forwarded` or `X-Forwarded-*` automatically.

## Bodies and trailers

Buffered and trailer adapters make body ownership, replayability, size limits,
streaming restrictions, and failure timing explicit. Adapter order determines
whether signatures cover coded or uncoded content. See
[integration](docs/integration.md) and [security](docs/security.md).

## Supported algorithms

The package implements every active RFC 9421 algorithm and SHA-256/SHA-512
RFC 9530 digests with strict key and signature bounds. Deprecated digest
algorithms are parseable for negotiation but never computed or accepted. See
[conformance](docs/conformance.md) for the exact profile.

## Legacy and vendor protocols

The [`compatibility`](compatibility) package provides explicitly named
`RoundTripper` and verification-middleware boundaries for Cavage draft
signatures, AWS Signature V4, OAuth 1.0, and named vendor schemes. Applications
must supply the actual protocol implementation; the boundary clones outbound
request metadata, preserves body ownership, sanitizes callback failures, and
never invokes or extends the RFC 9421 parsers. Outbound callbacks can emit
non-RFC-signature vendor fields, but cannot change request identity or RFC 9421
signature fields. Inbound callbacks operate on an isolated read-only view; none
of their request mutations reach later RFC verification. Do not install a
compatibility adapter and an RFC 9421 adapter as interchangeable authentication
paths.

## Documentation

Use the [documentation index](docs/README.md) for integration, conformance,
compatibility, security, benchmarks, and maintenance guidance.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
