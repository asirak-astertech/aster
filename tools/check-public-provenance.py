#!/usr/bin/env python3
"""Validate the public development-source disclosure register."""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "provenance" / "public-source-register.csv"
EXPECTED_HEADER = [
    "public_id",
    "category",
    "title",
    "version_or_date",
    "public_url",
    "license_or_status",
    "disposition",
    "used_for",
    "repository_evidence",
]
ALLOWED_CATEGORIES = {
    "public-specification",
    "security-guidance",
    "standard",
    "upstream-component",
    "upstream-project",
}
ALLOWED_DISPOSITIONS = {
    "bounded-pilot",
    "evaluated-not-selected",
    "external-gate",
    "interoperability-oracle",
    "selected-component",
    "standards-reference",
}
OPERATIONAL_ONLY_FRAGMENTS = (
    "accessed_utc",
    "authorization receipt",
    "chat transcript",
    "file://",
    "internal-only",
    "localhost",
    "privileged",
    "source_register.csv",
    "/private/",
    "/users/",
)


def fail(message: str) -> None:
    raise ValueError(message)


def validate_evidence(public_id: str, evidence: str) -> None:
    paths = [Path(value.strip()) for value in evidence.split(";") if value.strip()]
    if not paths:
        fail(f"{public_id}: repository_evidence is empty")
    for relative in paths:
        if relative.is_absolute() or ".." in relative.parts:
            fail(f"{public_id}: evidence path must be repository-relative: {relative}")
        resolved = (ROOT / relative).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            fail(f"{public_id}: evidence path escapes the repository: {relative}")
        if not resolved.is_file():
            fail(f"{public_id}: evidence path does not exist: {relative}")


def main() -> int:
    with REGISTER.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != EXPECTED_HEADER:
            fail(f"unexpected header: {reader.fieldnames!r}")
        rows = list(reader)

    if len(rows) < 40:
        fail("public source register unexpectedly contains fewer than 40 rows")

    seen_ids = set()
    seen_urls = set()
    expected_ids = [f"PUB-{index:03d}" for index in range(1, len(rows) + 1)]

    for index, row in enumerate(rows):
        public_id = row["public_id"]
        if public_id != expected_ids[index] or not re.fullmatch(r"PUB-[0-9]{3}", public_id):
            fail(f"row {index + 2}: expected {expected_ids[index]}, found {public_id!r}")
        if public_id in seen_ids:
            fail(f"duplicate public_id: {public_id}")
        seen_ids.add(public_id)

        for field in EXPECTED_HEADER:
            if not row[field].strip():
                fail(f"{public_id}: {field} is empty")

        if row["category"] not in ALLOWED_CATEGORIES:
            fail(f"{public_id}: unsupported category {row['category']!r}")
        if row["disposition"] not in ALLOWED_DISPOSITIONS:
            fail(f"{public_id}: unsupported disposition {row['disposition']!r}")

        parsed = urlsplit(row["public_url"])
        if parsed.scheme != "https" or not parsed.netloc:
            fail(f"{public_id}: public_url must be an absolute HTTPS URL")
        if row["public_url"] in seen_urls:
            fail(f"{public_id}: duplicate public_url {row['public_url']!r}")
        seen_urls.add(row["public_url"])

        serialized = " ".join(row.values()).lower()
        for fragment in OPERATIONAL_ONLY_FRAGMENTS:
            if fragment in serialized:
                fail(f"{public_id}: operational-only fragment is not public-register data")

        validate_evidence(public_id, row["repository_evidence"])

    print(f"validated {len(rows)} public provenance rows")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, csv.Error) as error:
        print(f"public provenance validation failed: {error}", file=sys.stderr)
        sys.exit(1)
