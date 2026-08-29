#!/usr/bin/env python3
"""Inspect locally built distributions without installing from the network."""
from __future__ import annotations

import argparse
import csv
import email.parser
import sys
import tarfile
import zipfile
from pathlib import Path


REQUIRED_PACKAGE_FILES = {
    "elcapitan/schemas/evidence-ref.schema.json",
    "elcapitan/schemas/finding-record.schema.json",
    "elcapitan/web/index.html",
    "elcapitan/shadow_web_assets/index.html",
    "elcapitan/review_web_assets/index.html",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    wheels = tuple(args.directory.glob("elcapitan-*.whl"))
    sdists = tuple(args.directory.glob("elcapitan-*.tar.gz"))
    errors: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1:
        errors.append("expected exactly one wheel and one source distribution")
    if wheels:
        with zipfile.ZipFile(wheels[0]) as archive:
            names = set(archive.namelist())
            missing = REQUIRED_PACKAGE_FILES - names
            errors.extend(f"wheel is missing {name}" for name in sorted(missing))
            metadata_name = next(
                (name for name in names if name.endswith(".dist-info/METADATA")), None
            )
            if metadata_name:
                metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_name))
                if metadata["Requires-Python"] != "==3.12.*":
                    errors.append("wheel does not pin Requires-Python to 3.12")
            record_name = next(
                (name for name in names if name.endswith(".dist-info/RECORD")), None
            )
            if record_name:
                rows = csv.reader(archive.read(record_name).decode().splitlines())
                if any(".env" in row[0] or "terraform.tfstate" in row[0] for row in rows):
                    errors.append("wheel contains a forbidden sensitive path")
    if sdists:
        with tarfile.open(sdists[0]) as archive:
            names = tuple(archive.getnames())
            if any("/.env" in name or "terraform.tfstate" in name for name in names):
                errors.append("source distribution contains a forbidden sensitive path")
    if errors:
        for error in errors:
            print(f"distribution error: {error}", file=sys.stderr)
        return 1
    print("distribution checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
