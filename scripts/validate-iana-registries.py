#!/usr/bin/env python3
"""Validate the pinned IANA registry projections against downloaded XML."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def direct_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if local_name(child) == name]


def text_value(element: ET.Element) -> str:
    return "".join(element.itertext())


def normalized(value: str) -> str:
    return " ".join(value.split())


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def xref_matches(element: ET.Element, expected: dict[str, str]) -> bool:
    if element.attrib.get("type") != expected["type"]:
        return False
    if element.attrib.get("data") != expected["data"]:
        return False
    if "section" in expected:
        return element.attrib.get("section") == expected["section"]
    return "section" not in element.attrib


def validate_xrefs(
    actual: list[ET.Element],
    expected: list[dict[str, str]],
    description: str,
) -> None:
    check(
        len(actual) == len(expected),
        f"{description} count mismatch: expected {len(expected)}, found {len(actual)}",
    )
    for index, expected_xref in enumerate(expected):
        check(
            xref_matches(actual[index], expected_xref),
            f"{description} at position {index + 1} does not match",
        )


def registry_for(source_file: Path, registry_id: str) -> ET.Element:
    try:
        root = ET.parse(source_file).getroot()
    except ET.ParseError as error:
        raise RuntimeError(f"could not parse {source_file}: {error}") from error
    registries = [
        element
        for element in root.iter()
        if local_name(element) == "registry" and element.attrib.get("id") == registry_id
    ]
    check(
        len(registries) == 1,
        f"registry {registry_id} expected exactly one definition, found {len(registries)}",
    )
    return registries[0]


def validate_registry(
    registry: dict[str, Any],
    source_files: dict[str, Path],
) -> None:
    registry_id = registry["registry_id"]
    registry_element = registry_for(
        source_files[registry["source_name"]],
        registry_id,
    )
    records = direct_children(registry_element, "record")
    expected_records = registry["records"]
    if registry["scope"] == "complete":
        check(
            len(records) == len(expected_records),
            f"registry {registry_id} record count mismatch: expected {len(expected_records)}, found {len(records)}",
        )

    metadata = registry.get("metadata", {})
    expected_note = metadata.get("note_text")
    if expected_note:
        notes = direct_children(registry_element, "note")
        check(
            len(notes) == 1 and normalized(text_value(notes[0])) == expected_note,
            f"registry {registry_id} deprecation note does not exactly match the pinned text",
        )
        note = notes[0]
        segments = []
        if note.text:
            segments.append(normalized(note.text))
        segments.extend(
            normalized(child.tail)
            for child in note
            if child.tail
        )
        check(
            segments == metadata["note_text_segments"],
            f"registry {registry_id} deprecation note text segments do not match their pinned placement",
        )
        validate_xrefs(
            direct_children(note, "xref"),
            metadata["note_xrefs"],
            f"registry {registry_id} deprecation note xref",
        )

    if "registry_xrefs" in metadata:
        validate_xrefs(
            direct_children(registry_element, "xref"),
            metadata["registry_xrefs"],
            f"registry {registry_id} direct xref",
        )

    key_element = registry["key_element"]
    for expected_record in expected_records:
        expected_key = expected_record["key"]
        matches = [
            record
            for record in records
            if any(
                text_value(child) == expected_key
                for child in direct_children(record, key_element)
            )
        ]
        check(
            len(matches) == 1,
            f"registry {registry_id} key {expected_key} has {len(matches)} records, expected exactly one",
        )
        record = matches[0]
        for field, expected_value in expected_record["fields"].items():
            values = direct_children(record, field)
            check(
                len(values) >= 1 and text_value(values[0]) == expected_value,
                f"registry {registry_id} key {expected_key} field {field} mismatch",
            )

        if "direct_xrefs" in expected_record:
            validate_xrefs(
                direct_children(record, "xref"),
                expected_record["direct_xrefs"],
                f"registry {registry_id} key {expected_key} direct xref",
            )

        expected_comments = expected_record.get("comments")
        if expected_comments:
            comments = direct_children(record, "comments")
            check(
                len(comments) == 1
                and normalized(text_value(comments[0])) == expected_comments["text"],
                f"registry {registry_id} key {expected_key} comments do not exactly match the pinned relationship",
            )
            validate_xrefs(
                direct_children(comments[0], "xref"),
                expected_comments["xrefs"],
                f"registry {registry_id} key {expected_key} comment xref",
            )

    print(f"verified IANA registry {registry_id} ({len(expected_records)} records)")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} LOCK_FILE WORK_DIRECTORY", file=sys.stderr)
        return 2
    lock = json.loads(Path(sys.argv[1]).read_text())
    work_directory = Path(sys.argv[2])
    source_files = {
        source["name"]: work_directory / f"source-{index}"
        for index, source in enumerate(lock["sources"])
    }
    try:
        for registry in lock["registries"]:
            validate_registry(registry, source_files)
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
