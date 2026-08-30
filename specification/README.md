# HTTP Message Signature decision conformance

The canonical [specification decision register](../docs/specification-decisions.md)
records each selected policy. The [normative matrix](../docs/conformance.md),
[source monitor](../spec/errata-decisions.md), and
[maintained-peer inventory](../spec/interoperability.md) provide detailed evidence.

## Decision matrix

| Decision | Executable evidence | Differential status |
| --- | --- | --- |
| HTTP-SIG-DEC-001: RFC 8941 parsing model and dialect boundary | `TestHTTPWGRFC8941Corpus` | deliberate policy difference |
| HTTP-SIG-DEC-002: Hostile-input and canonical-base resource ceilings | `TestRawSyntaxLimitsAcceptExactLimitsAndRejectTheirNeighbors` | not assessed |
| HTTP-SIG-DEC-003: Complete-field combination, ordering, and duplicates | `TestParseSignaturesPreservesOrderAndCopiesBytes` | maintained peer agreement |
| HTTP-SIG-DEC-004: Covered-component identity and extension parameters | `TestVerificationProfileMatchesRequiredComponentParametersIndependentOfOrder` | maintained peer agreement |
| HTTP-SIG-DEC-005: Request-target reconstruction and trusted proxy context | `TestCreateSignatureBaseUsesExplicitExternalRequestTargetThroughout` | maintained peer agreement |
| HTTP-SIG-DEC-006: Query parameter decoding and duplicate values | `TestQueryParameterUsesHTMLFormParsing` | maintained peer agreement |
| HTTP-SIG-DEC-007: Structured, binary, trailer, and related-request modes | `TestComponentParameterAndResolutionBoundaries` | maintained peer agreement |
| HTTP-SIG-DEC-008: Application profiles and signature metadata policy | `TestSigningProfileRequiresExplicitCoherentPolicy` | not assessed |
| HTTP-SIG-DEC-009: Multiple signatures, label matching, and selection | `TestVerifierRejectsDifferentLabelSetsBeforeSelection` | deliberate policy difference |
| HTTP-SIG-DEC-010: Algorithm registry, strict key binding, and randomness | `TestRFC9421AppendixBAlgorithmVectors` | maintained peer agreement |
| HTTP-SIG-DEC-011: Key resolution, rotation, revocation, and safe failures | `TestVerifierLifecycleKeyRotationAndRevocation` | not assessed |
| HTTP-SIG-DEC-012: Replay identity and atomic nonce consumption | `TestMemoryReplayStoreAllowsExactlyOneConcurrentConsumer` | not assessed |
| HTTP-SIG-DEC-013: Digest algorithms, deprecated names, and representation | `TestDigestParserAndVerifierBoundarySemantics` | not assessed |
| HTTP-SIG-DEC-014: Buffered body ownership and digest release | `TestVerifyingRoundTripperVerifiesContentDigestAndReturnsReplayableCodedBody` | not assessed |
| HTTP-SIG-DEC-015: Trailer finality, streaming, and retry ownership | `TestTrailerSigningRoundTripperStreamsDigestAndSignatureAtEOF` | not assessed |
| HTTP-SIG-DEC-016: Response signatures and immutable related requests | `TestVerifyingRoundTripperBindsReqComponentsToImmutableActualSentRequest` | not assessed |
| HTTP-SIG-DEC-017: Cryptographic validity is not authorization | `TestVerifierReturnsSafeTypedFailuresForPolicyTimeAndKeyErrors` | not assessed |
| HTTP-SIG-DEC-018: Legacy and vendor protocol isolation | `TestHTTPAdaptersRejectCaseCollidingProtectedFields` | not assessed |
| HTTP-SIG-DEC-019: Errata and registry changes do not silently change behavior | `TestNISTP384SHA384VerificationVector` | not assessed |
| HTTP-SIG-DEC-020: Net/http wire identity is explicit and fail closed | `TestSignatureBaseUsesNetHTTPTransportManagedRequestFields` | not assessed |
