#!/usr/bin/env bash
set -euo pipefail

module_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${module_root}/spec/sources.lock.json"
work="$(mktemp -d "${TMPDIR:-/tmp}/http-signature-sources.XXXXXX")"
cleanup() {
    find "${work}" -type f -delete
    rmdir "${work}"
}
trap cleanup EXIT HUP INT TERM

command -v curl >/dev/null
command -v jq >/dev/null
command -v shasum >/dev/null
command -v python3 >/dev/null

jq -e '
    def valid_xref:
        (type == "object") and
        (all(keys[]; IN("type", "data", "section"))) and
        (.type | IN("rfc", "registry")) and
        (.data | type == "string" and test("^[A-Za-z0-9-]+$")) and
        ((has("section") | not) or (.section | type == "string" and test("^[0-9]+(\\.[0-9]+)*$")));
    def unique_xrefs:
        map([.type, .data, (.section // "")] | join("|")) |
        length == (unique | length);
    .schema_version == 2 and
    (.retrieved_at | type == "string" and length > 0) and
    (.sources | type == "array" and length == 12) and
    ([.sources[].name] | length == (unique | length)) and
    ([.sources[] | select(.kind == "normative-rfc") | .name] | sort == ["RFC 8941 text", "RFC 9421 text", "RFC 9530 text"]) and
    ([.sources[] | select(.kind == "rfc-errata") | .name] | sort == ["RFC 8941 errata records", "RFC 9421 errata records", "RFC 9530 errata records"]) and
    ([.sources[] | select(.kind == "iana-registry") | .name] | sort == ["IANA HTTP Field Name registry", "IANA HTTP Message Signature registries", "IANA Hash Algorithms for HTTP Digest Fields registry", "IANA legacy HTTP Digest Algorithm Values registry"]) and
    ([.sources[] | select(.kind == "interoperability-corpus") | .name] == ["HTTPWG RFC 8941 Structured Fields corpus"]) and
    ([.sources[] | select(.kind == "cryptographic-vector-corpus") | .name] == ["NIST CAVP FIPS 186-3 ECDSA test vectors"]) and
    all(.sources[];
        (.name | type == "string" and length > 0) and
        (.kind | type == "string" and length > 0) and
        (.url | type == "string" and startswith("https://")) and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
    ) and
    all(.sources[] | select(.kind == "interoperability-corpus");
        . as $source |
        ($source.revision | type == "string" and test("^[0-9a-f]{40}$")) and
        ($source.url | endswith($source.revision)) and
        ($source.scope | type == "string" and length > 0) and
        ($source.license | type == "string" and length > 0)
    ) and
    all(.sources[] | select(.kind == "iana-registry");
        (.last_modified | type == "string" and length > 0)
    ) and
    (.errata | type == "array" and length == 3) and
    ([.errata[].rfc] | sort == [8941, 9421, 9530]) and
    ([.errata[].source_name] | length == (unique | length)) and
    all(.errata[]; .source_name == ("RFC " + (.rfc | tostring) + " errata records")) and
    all(.errata[];
        (.rfc | type == "number") and
        (.source_name | type == "string" and length > 0) and
        (.records | type == "array") and
        all(.records[];
            (.id | type == "number") and
            (.status | IN("Verified", "Reported", "Held for Document Update", "Rejected")) and
            (.type | IN("Editorial", "Technical"))
        )
    ) and
    (.registries | type == "array" and length == 7) and
    ([.registries[].registry_id] | sort == ["component-parameters", "digest-fields", "field-names", "http-dig-alg-1", "signature-algorithms", "signature-derived-component-names", "signature-metadata-parameters"]) and
    ([.registries[] | [.source_name, .registry_id, .scope] | join("|")] | sort == [
        "IANA HTTP Field Name registry|field-names|selected-package-fields",
        "IANA HTTP Message Signature registries|component-parameters|complete",
        "IANA HTTP Message Signature registries|signature-algorithms|complete",
        "IANA HTTP Message Signature registries|signature-derived-component-names|complete",
        "IANA HTTP Message Signature registries|signature-metadata-parameters|complete",
        "IANA Hash Algorithms for HTTP Digest Fields registry|digest-fields|complete",
        "IANA legacy HTTP Digest Algorithm Values registry|http-dig-alg-1|complete"
    ]) and
    ([.registries[] | select(.registry_id == "field-names") | .records[].key] | sort == [
        "Accept-Signature",
        "Content-Digest",
        "Digest",
        "Repr-Digest",
        "Signature",
        "Signature-Input",
        "Want-Content-Digest",
        "Want-Digest",
        "Want-Repr-Digest"
    ]) and
    all(.registries[] | select(.registry_id == "http-dig-alg-1");
        .metadata == {
            "note_text": "This registry is deprecated since it lists the algorithms that can be used with the Digest and Want-Digest fields defined in , which has been obsoleted by . While registration is not closed, new registrations are encouraged to use the Hash Algorithms for HTTP Digest Fields registry instead.",
            "note_text_segments": [
                "This registry is deprecated since it lists the algorithms that can be used with the Digest and Want-Digest fields defined in",
                ", which has been obsoleted by",
                ". While registration is not closed, new registrations are encouraged to use the",
                "registry instead."
            ],
            "registry_xrefs": [{"type": "rfc", "data": "rfc3230"}],
            "note_xrefs": [
                {"type": "rfc", "data": "rfc3230"},
                {"type": "rfc", "data": "rfc9530"},
                {"type": "registry", "data": "http-digest-hash-alg"}
            ]
        }
    ) and
    all(.registries[] | select(.registry_id == "field-names") | .records[] | select(.key == "Digest" or .key == "Want-Digest");
        .direct_xrefs == [{"type": "rfc", "data": "rfc3230"}] and
        .comments == {
            "text": "Obsoleted by RFC 9530, Section 1.3: Digest Fields",
            "xrefs": [{"type": "rfc", "data": "rfc9530", "section": "1.3"}]
        }
    ) and
    all(.registries[];
        (.source_name | type == "string" and length > 0) and
        (.registry_id | type == "string" and test("^[a-z0-9-]+$")) and
        (.key_element | IN("name", "key", "value")) and
        (.scope | IN("complete", "selected-package-fields")) and
        (.records | type == "array" and length > 0) and
        ([.records[].key] | length == (unique | length)) and
        ((has("metadata") | not) or
            ((.metadata | type == "object") and
             (all(.metadata | keys[]; IN("note_text", "note_text_segments", "note_xrefs", "registry_xrefs"))) and
             (.metadata.note_text | type == "string" and length > 0) and
             (.metadata.note_text_segments | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)) and
             (.metadata.note_xrefs | type == "array" and length > 0 and unique_xrefs and all(.[]; valid_xref)) and
             (.metadata.registry_xrefs | type == "array" and length > 0 and unique_xrefs and all(.[]; valid_xref)))) and
        all(.records[];
            (all(keys[]; IN("comments", "direct_xrefs", "fields", "key"))) and
            (.key | type == "string" and test("^[A-Za-z0-9@._-]+$")) and
            (.fields | type == "object") and
            all(.fields | keys[]; IN("status", "target", "structured")) and
            all(.fields[]; type == "string" and length > 0) and
            ((.direct_xrefs // []) | type == "array" and unique_xrefs and all(.[]; valid_xref)) and
            ((has("comments") | not) or
                ((.comments | type == "object") and
                 (all(.comments | keys[]; IN("text", "xrefs"))) and
                 (.comments.text | type == "string" and length > 0) and
                 (.comments.xrefs | type == "array" and length > 0 and unique_xrefs and all(.[]; valid_xref))))
        )
    )
' "${lock_file}" >/dev/null

source_count="$(jq -r '.sources | length' "${lock_file}")"
for ((source_index = 0; source_index < source_count; source_index++)); do
    name="$(jq -er --argjson index "${source_index}" '.sources[$index].name' "${lock_file}")"
    url="$(jq -er --argjson index "${source_index}" '.sources[$index].url' "${lock_file}")"
    expected="$(jq -er --argjson index "${source_index}" '.sources[$index].sha256' "${lock_file}")"
    source_file="${work}/source-${source_index}"
    header_file="${work}/headers-${source_index}"

    curl --fail --silent --show-error --location "${url}" --dump-header "${header_file}" --output "${source_file}"
    actual="$(shasum -a 256 "${source_file}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        printf 'pinned source changed: %s\nexpected %s\nactual   %s\n' "${name}" "${expected}" "${actual}" >&2
        exit 1
    fi
    expected_last_modified="$(jq -r --argjson index "${source_index}" '.sources[$index].last_modified // empty' "${lock_file}")"
    if [[ -n "${expected_last_modified}" ]]; then
        actual_last_modified="$(awk 'tolower($1) == "last-modified:" {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); value=$0} END {print value}' "${header_file}")"
        if [[ "${actual_last_modified}" != "${expected_last_modified}" ]]; then
            printf 'source Last-Modified changed: %s\nexpected %s\nactual   %s\n' "${name}" "${expected_last_modified}" "${actual_last_modified}" >&2
            exit 1
        fi
    fi
    printf 'verified %s\n' "${name}"
done

errata_count="$(jq -r '.errata | length' "${lock_file}")"
for ((errata_index = 0; errata_index < errata_count; errata_index++)); do
    source_name="$(jq -er --argjson index "${errata_index}" '.errata[$index].source_name' "${lock_file}")"
    source_index="$(jq -er --arg name "${source_name}" '.sources | to_entries[] | select(.value.name == $name) | .key' "${lock_file}")"
    source_file="${work}/source-${source_index}"
    actual_file="${work}/errata-${errata_index}.actual"
    expected_file="${work}/errata-${errata_index}.expected"

    perl -0777 -ne '
        while (/Errata-ID:.*?eid(\d+).*?Status:<\/dt>\s*<dd[^>]*>\s*<span[^>]*>([^<]+).*?Type:<\/dt>\s*<dd[^>]*>\s*<span[^>]*>([^<]+)/sg) {
            my ($id, $status, $type) = ($1, $2, $3);
            $status =~ s/^\s+|\s+$//g;
            $type =~ s/^\s+|\s+$//g;
            print "$id\t$status\t$type\n";
        }
    ' "${source_file}" | sort -n >"${actual_file}"
    jq -r --argjson index "${errata_index}" '.errata[$index].records[] | [.id, .status, .type] | @tsv' "${lock_file}" | sort -n >"${expected_file}"
    if ! diff -u "${expected_file}" "${actual_file}"; then
        printf 'errata inventory does not match %s\n' "${source_name}" >&2
        exit 1
    fi
done

python3 "${module_root}/scripts/validate-iana-registries.py" "${lock_file}" "${work}"
