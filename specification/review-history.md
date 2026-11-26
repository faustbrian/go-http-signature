# Upstream review history

## 2026-11-26: IANA registry monitoring review

The three IANA registry documents whose digests no longer matched their
monitoring pins were retrieved twice over HTTPS with the same request profile
as the online specification check. Each pair of retrievals produced the same
digest. The RFC 8941, RFC 9421 and RFC 9530 texts, their errata records and
the NIST CAVP FIPS 186-3 vectors still match their pins. The thirty-day cadence
and all authority URLs remain unchanged.

| Authorities | Previous SHA-256 | Current SHA-256 |
| --- | --- | --- |
| `iana-http-digest-algorithms`, `iana-http-digest-algorithms-updates` | `6336a1abc58420f6fcabab4a0cd999ce3c0a8f12e034e543f05edf342cf927e7` | `a4013ac2108616b7395fd7e481bd342814d0d182faf0a15580121fe04776c636` |
| `iana-http-fields`, `iana-http-fields-updates` | `e9c70a0dd680385e8c7aae1da0c585794306f65b63636148623d1e2c0533cf1d` | `a279742590892cdb58177f7928d57f2577d3a3b898cd86eb0b26aa9c4f5ec096` |
| `iana-http-message-signature`, `iana-http-message-signature-updates` | `bd4b0304e21e226fef189ed283a31392b5ffc99a37d00e9911dc011dcfb1523f` | `7311fb3d38d8f5d93b32fdfbb38ec6103c512b71380ef4f9545ffddeba862e22` |

The Hash Algorithms for HTTP Digest Fields registry still reports its last
update as 2024-05-22. A public archive copy from 2026-06-12 reproduces the
previous pinned digest exactly, and comparing it with the current document
shows only cross-reference markup changes: the NO-MD5 and NO-SHA references
became RFC references, the two UNIX references became draft references, and
the RFC 9260 appendix reference gained an `appendix` attribute. All eight
keys and their Active or Deprecated statuses are unchanged, so
`HTTP-SIG-DEC-013` and the locked digest-algorithm records are unaffected.

The HTTP Field Name registry now reports its last update as 2026-11-02. Its
recent entries, such as `No-Vary-Search` (updated 2026-10-09), concern fields
this package does not sign, verify or parse. The nine fields the package locks
(`Accept-Signature`, `Content-Digest`, `Digest`, `Repr-Digest`, `Signature`,
`Signature-Input`, `Want-Content-Digest`, `Want-Digest` and
`Want-Repr-Digest`) keep their registered status and structured type. The
prior document body was not retained, so this review does not enumerate every
other byte difference; none of them touches a field the package locks.

Neither change alters a decision, conformance binding or runtime behavior.

The HTTP Message Signature registry now reports its last update as
2026-10-23. On that date it registered `ml-dsa-44`, `ml-dsa-65` and
`ml-dsa-87` as Active signature algorithms, citing the C2SP httpsig-pq v1.0.1
specification. Its other three registries (metadata parameters, derived
component names and component parameters) are unchanged. The new algorithms
fall within `HTTP-SIG-DEC-010`, which previously accepted "only active
registered algorithms" while the package implements six. The decision now
closes the accepted set to the six RFC 9421 algorithms and records the three
ML-DSA identifiers as registered but unsupported. The package already rejected
them: `Sign` and `Verify` return `ErrUnsupportedSignatureAlgorithm` and signing
and verification profiles refuse them, which
`TestRegisteredButUnsupportedMLDSAAlgorithmsAreRejected` now asserts. The
decision version and the registry's monitoring version move to 2026-10-23,
and the field-name registry's monitoring version moves to 2026-11-02.

The pinned registry sources in `spec/sources.lock.json` were refreshed with
the same digests and current `Last-Modified` values, and the complete
signature-algorithm projection now lists the three ML-DSA records. The legacy
HTTP Digest Algorithm Values registry also changed on 2026-10-13
(`8e2ee05465e8973b63567ef82c9c4f58e56c14a460c288853ce0f90faba027ec` to
`e9a4c94c96ed26edbaebd1adf21aba1f4b6c29daa7f61a04c6cf4519137c5a87`). A public
archive copy reproduces its previous digest, and the only differences are
cross-reference markup: the ADLER32 description links RFC 1950 and the
RFC 9260 reference uses an `appendix` attribute. Its eight records and its
deprecation note are unchanged.

No runtime behavior changes.
