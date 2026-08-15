#!/usr/bin/env python3
"""Extract XML/XSD examples embedded as text in official API DOCX files.

The generated files are *evidence*, not automatically trusted request
templates.  ``inventory.json`` records the exact DOCX/table/cell, source hash,
content hash and parse result so a service profile can select a reviewed block
without silently inheriting another service's XML.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from docx import Document

try:
    from lxml import etree
except ImportError:  # pragma: no cover - extraction still works without lxml
    etree = None


ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = ROOT / "docs" / "api_for_gu"
OUTPUT_ROOT = DOCS_ROOT / "extracted"
XML_DECLARATION = re.compile(r"<\?xml\s", re.IGNORECASE)
ROOT_ELEMENT = re.compile(r"<([A-Za-zА-Яа-я_][\wА-Яа-я.-]*:)?([A-Za-zА-Яа-я_][\wА-Яа-я.-]*)\b")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate(text: str) -> Optional[str]:
    value = text.strip().replace("\ufeff", "")
    declaration = XML_DECLARATION.search(value)
    if declaration:
        value = value[declaration.start() :].strip()
    if not value.startswith("<") or len(value) < 100:
        return None
    root = ROOT_ELEMENT.search(value)
    if not root:
        return None
    local_name = root.group(2).lower()
    document_roots = {
        "schema",
        "request",
        "response",
        "order",
        "orderresponse",
        "epgurequest",
        "irequest",
        "irequestother",
        "petition",
        "signrequest",
        "formdata",
        "service_10000004558",
        "эдпфр",
        "эдсфр",
    }
    if local_name not in document_roots and "<xs:schema" not in value and "<xsd:schema" not in value:
        return None
    return value.replace("\r\n", "\n").replace("\r", "\n") + "\n"


def _blocks(path: Path) -> Iterator[Tuple[str, int, int, int]]:
    document = Document(path)
    seen = set()
    for table_index, table in enumerate(document.tables):
        for row_index, row in enumerate(table.rows):
            for cell_index, cell in enumerate(row.cells):
                value = _candidate(cell.text)
                if value is None:
                    continue
                digest = _sha256_bytes(value.encode("utf-8"))
                # Merged Word cells are repeated in python-docx; retain one copy.
                if digest in seen:
                    continue
                seen.add(digest)
                yield value, table_index, row_index, cell_index


def _inspect_xml(value: str) -> Dict[str, Any]:
    match = ROOT_ELEMENT.search(value)
    root_name = (match.group(1) or "") + match.group(2) if match else ""
    result: Dict[str, Any] = {"rootName": root_name}
    if etree is None:
        result.update({"wellFormed": None, "parseError": "lxml is not installed"})
        return result
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
        root = etree.fromstring(value.encode("utf-8"), parser=parser)
        qname = etree.QName(root)
        result.update(
            {
                "wellFormed": True,
                "rootName": qname.localname,
                "namespace": qname.namespace or "",
            }
        )
    except Exception as exc:
        result.update({"wellFormed": False, "parseError": str(exc).split("\n", 1)[0]})
    return result


def extract() -> int:
    catalogue = json.loads((DOCS_ROOT / "catalog.json").read_text(encoding="utf-8"))
    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)
    OUTPUT_ROOT.mkdir(parents=True)
    inventory: List[Dict[str, Any]] = []
    for document_item in catalogue["documents"]:
        code = document_item.get("serviceCode")
        if not code or not str(document_item["file"]).lower().endswith(".docx"):
            continue
        source_path = DOCS_ROOT / document_item["file"]
        service_dir = OUTPUT_ROOT / str(code)
        service_dir.mkdir(parents=True, exist_ok=True)
        example_number = 0
        schema_number = 0
        for value, table_index, row_index, cell_index in _blocks(source_path):
            inspected = _inspect_xml(value)
            is_schema = inspected.get("rootName", "").lower().endswith("schema")
            if is_schema:
                schema_number += 1
                name = "schema-{:02d}.xsd".format(schema_number)
            else:
                example_number += 1
                name = "example-{:02d}.xml".format(example_number)
            destination = service_dir / name
            encoded = value.encode("utf-8")
            destination.write_bytes(encoded)
            record: Dict[str, Any] = {
                "serviceCode": code,
                "asset": str(destination.relative_to(DOCS_ROOT)).replace("\\", "/"),
                "kind": "schema" if is_schema else "example",
                "source": document_item["file"],
                "sourceSha256": _sha256_file(source_path),
                "table": table_index,
                "row": row_index,
                "cell": cell_index,
                "bytes": len(encoded),
                "sha256": _sha256_bytes(encoded),
                **inspected,
            }
            inventory.append(record)

    inventory_path = OUTPUT_ROOT / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "catalogObservedAt": catalogue["catalogObservedAt"],
                "warning": "Extracted examples require profile-level review before submission.",
                "assets": inventory,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Extracted {} XML/XSD blocks to {}".format(len(inventory), OUTPUT_ROOT))
    return 0


def verify() -> int:
    """Verify generated evidence without modifying the working tree."""
    catalogue = json.loads((DOCS_ROOT / "catalog.json").read_text(encoding="utf-8"))
    inventory_path = OUTPUT_ROOT / "inventory.json"
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print("Invalid extraction inventory: {}".format(exc))
        return 1
    if inventory.get("schemaVersion") != 1 or not isinstance(inventory.get("assets"), list):
        print("Unsupported extraction inventory schema")
        return 1

    documents = {
        str(item.get("serviceCode")): item
        for item in catalogue["documents"]
        if item.get("serviceCode")
    }
    failures: List[str] = []
    seen = set()
    for item in inventory["assets"]:
        asset_name = str(item.get("asset") or "")
        if asset_name in seen:
            failures.append("duplicate asset {}".format(asset_name))
        seen.add(asset_name)
        code = str(item.get("serviceCode") or "")
        document = documents.get(code)
        if document is None:
            failures.append("{}: unknown serviceCode {}".format(asset_name, code))
            continue
        source_path = DOCS_ROOT / str(document["file"])
        asset_path = DOCS_ROOT / asset_name
        if not source_path.is_file() or _sha256_file(source_path) != item.get("sourceSha256"):
            failures.append("{}: source hash mismatch".format(asset_name))
        if not asset_path.is_file() or _sha256_file(asset_path) != item.get("sha256"):
            failures.append("{}: asset hash mismatch".format(asset_name))

    print(
        "Verified {} extracted XML/XSD blocks; failures={}".format(
            len(inventory["assets"]), len(failures)
        )
    )
    for failure in failures:
        print("- {}".format(failure))
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify checked-in assets and hashes without rewriting them",
    )
    args = parser.parse_args()
    return verify() if args.check else extract()


if __name__ == "__main__":
    raise SystemExit(main())
