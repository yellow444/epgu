#!/usr/bin/env python3
"""Create a deterministic, machine-readable repository quality audit.

This is a structural audit, not a proof of business correctness.  Contract
correctness is additionally enforced by unit/golden tests and by hashes of the
official source documents recorded in ``docs/api_for_gu``.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import tokenize
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "code_audit.json"
SCHEMA_VERSION = 1
OBSERVED_AT = "2026-08-12"
SOURCE_ROOTS = (
    ROOT / "api-gosuslugi-backend",
    ROOT / "api-gosuslugi-client" / "src",
    ROOT / "python-epgu" / "src",
    ROOT / "python-epgu" / "tests",
    ROOT / "scripts",
)
EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _files(suffixes: Sequence[str]) -> List[Path]:
    result = []
    for source_root in SOURCE_ROOTS:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            if (
                path.is_file()
                and path.suffix.lower() in suffixes
                and not any(part in EXCLUDED_PARTS for part in path.parts)
            ):
                result.append(path)
    return sorted(set(result), key=_relative)


def _loc(text: str, comment_lines: Iterable[int]) -> Dict[str, int]:
    lines = text.splitlines()
    comments = set(comment_lines)
    blank = sum(not line.strip() for line in lines)
    comment_only = sum(
        line_number in comments and bool(line.strip())
        for line_number, line in enumerate(lines, start=1)
    )
    return {
        "total": len(lines),
        "blank": blank,
        "commentOnly": comment_only,
        "codeOrMixed": len(lines) - blank - comment_only,
    }


def _percent(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 1) if denominator else 100.0


def _is_public(name: str) -> bool:
    return not name.startswith("_")


def _python_audit(paths: Sequence[Path]) -> Dict[str, Any]:
    totals: Counter[str] = Counter()
    parse_errors = []
    file_metrics = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        comment_lines = []
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type == tokenize.COMMENT:
                    comment_lines.extend(range(token.start[0], token.end[0] + 1))
        except (IndentationError, tokenize.TokenError):
            pass
        loc = _loc(text, comment_lines)
        totals.update({"files": 1, **loc})
        try:
            tree = ast.parse(text, filename=_relative(path))
        except SyntaxError as exc:
            parse_errors.append(
                {"file": _relative(path), "line": exc.lineno, "message": exc.msg}
            )
            continue

        parent: Dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parent[child] = node

        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        methods = [node for node in functions if isinstance(parent.get(node), ast.ClassDef)]
        module_functions = [node for node in functions if isinstance(parent.get(node), ast.Module)]
        public_api = [node for node in module_functions + classes + methods if _is_public(node.name)]
        documented = [node for node in public_api if ast.get_docstring(node)]
        arguments = []
        for node in functions:
            positional = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            arguments.extend(arg for arg in positional if arg.arg not in {"self", "cls"})
            if node.args.vararg:
                arguments.append(node.args.vararg)
            if node.args.kwarg:
                arguments.append(node.args.kwarg)
        annotated_arguments = [arg for arg in arguments if arg.annotation is not None]
        public_functions = [node for node in module_functions + methods if _is_public(node.name)]
        annotated_returns = [node for node in public_functions if node.returns is not None]
        assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
        annotated_assignments = [node for node in assignments if isinstance(node, ast.AnnAssign)]
        test_cases = [node for node in functions if node.name.startswith("test")]
        async_functions = [node for node in functions if isinstance(node, ast.AsyncFunctionDef)]

        metric = {
            "file": _relative(path),
            "functions": len(module_functions),
            "classes": len(classes),
            "methods": len(methods),
            "asyncFunctions": len(async_functions),
            "variables": len(assignments),
            "annotatedVariables": len(annotated_assignments),
            "publicApi": len(public_api),
            "documentedPublicApi": len(documented),
            "arguments": len(arguments),
            "annotatedArguments": len(annotated_arguments),
            "publicCallableReturns": len(public_functions),
            "annotatedPublicReturns": len(annotated_returns),
            "testCases": len(test_cases),
            "loc": loc,
        }
        file_metrics.append(metric)
        for key, value in metric.items():
            if key not in {"file", "loc"}:
                totals[key] += int(value)

    result = dict(totals)
    result.update(
        {
            "parseErrors": parse_errors,
            "publicDocumentationPercent": _percent(
                totals["documentedPublicApi"], totals["publicApi"]
            ),
            "argumentAnnotationPercent": _percent(
                totals["annotatedArguments"], totals["arguments"]
            ),
            "returnAnnotationPercent": _percent(
                totals["annotatedPublicReturns"], totals["publicCallableReturns"]
            ),
            "variableAnnotationPercent": _percent(
                totals["annotatedVariables"], totals["variables"]
            ),
            "byFile": file_metrics,
        }
    )
    return result


def _javascript_comment_lines(lines: Sequence[str]) -> List[int]:
    comments = []
    inside_block = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if inside_block:
            comments.append(number)
            if "*/" in stripped:
                inside_block = False
            continue
        if stripped.startswith("//"):
            comments.append(number)
        if stripped.startswith("/*"):
            comments.append(number)
            inside_block = "*/" not in stripped
    return comments


def _javascript_audit(paths: Sequence[Path]) -> Dict[str, Any]:
    totals: Counter[str] = Counter()
    by_file = []
    patterns = {
        "functionsApprox": re.compile(
            r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        ),
        "classes": re.compile(r"\bclass\s+[A-Za-z_$][\w$]*"),
        "variables": re.compile(r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*"),
        "exports": re.compile(r"\bexport\s+(?:default\s+)?(?:function|class|const|let|var|\{)"),
        "testCases": re.compile(r"\b(?:test|it)\s*\("),
        "jsdocBlocks": re.compile(r"/\*\*[\s\S]*?\*/"),
    }
    for path in paths:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        loc = _loc(text, _javascript_comment_lines(lines))
        metric: Dict[str, Any] = {"file": _relative(path), "loc": loc}
        for name, pattern in patterns.items():
            metric[name] = len(pattern.findall(text))
        by_file.append(metric)
        totals.update({"files": 1, **loc})
        for key in patterns:
            totals[key] += metric[key]
    return {
        **dict(totals),
        "parser": "conservative regular-expression inventory; ESLint/Jest provide syntax validation",
        "byFile": by_file,
    }


def _service_contract_audit() -> Dict[str, Any]:
    profile_path = ROOT / "api-gosuslugi-backend" / "service_profiles.json"
    profile_payload = json.loads(profile_path.read_text(encoding="utf-8"))
    services = profile_payload["services"]
    modes: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    signatures: Counter[str] = Counter()
    documents = 0
    failures = []
    for code, profile in services.items():
        modes[profile["submission"]["mode"]] += 1
        statuses[profile["status"]] += 1
        for document in profile["submission"]["documents"]:
            documents += 1
            signatures[document["signature"]] += 1
            source_file = document.get("sourceFile")
            if source_file and not (ROOT / "api-gosuslugi-backend" / "xml" / source_file).is_file():
                failures.append("{}: missing sourceFile {}".format(code, source_file))
            schema_file = document.get("schemaFile")
            if schema_file and not (ROOT / "api-gosuslugi-backend" / "xml" / schema_file).is_file():
                failures.append("{}: missing schemaFile {}".format(code, schema_file))
        spec = profile["spec"]
        spec_path = ROOT / "docs" / "api_for_gu" / spec["localFile"]
        if not spec_path.is_file() or _sha256(spec_path) != spec["sha256"]:
            failures.append("{}: specification hash mismatch".format(code))
        for asset in profile.get("officialAssets", []):
            asset_path = ROOT / "docs" / "api_for_gu" / asset["path"]
            if not asset_path.is_file() or _sha256(asset_path) != asset["sha256"]:
                failures.append("{}: official asset mismatch {}".format(code, asset["path"]))
    return {
        "profileSchemaVersion": profile_payload["schemaVersion"],
        "catalogObservedAt": profile_payload["catalogObservedAt"],
        "services": len(services),
        "availableServices": sum(bool(value["available"]) for value in services.values()),
        "referenceOnlyServices": sum(not bool(value["available"]) for value in services.values()),
        "documents": documents,
        "modes": dict(sorted(modes.items())),
        "statuses": dict(sorted(statuses.items())),
        "documentSignatures": dict(sorted(signatures.items())),
        "integrityFailures": failures,
    }


def _documentation_audit() -> Dict[str, Any]:
    markdown = sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED_PARTS for part in path.parts)
    )
    lines = sum(len(path.read_text(encoding="utf-8", errors="replace").splitlines()) for path in markdown)
    return {"markdownFiles": len(markdown), "markdownLines": lines}


def build_report() -> Dict[str, Any]:
    python_files = _files((".py",))
    javascript_files = _files((".js", ".jsx"))
    catalogue = json.loads(
        (ROOT / "docs" / "api_for_gu" / "catalog.json").read_text(encoding="utf-8")
    )
    extraction = json.loads(
        (ROOT / "docs" / "api_for_gu" / "extracted" / "inventory.json").read_text(
            encoding="utf-8"
        )
    )
    report = {
        "schemaVersion": SCHEMA_VERSION,
        "observedAt": OBSERVED_AT,
        "scope": [str(path.relative_to(ROOT)).replace("\\", "/") for path in SOURCE_ROOTS],
        "python": _python_audit(python_files),
        "javascript": _javascript_audit(javascript_files),
        "serviceContracts": _service_contract_audit(),
        "officialDocuments": {
            "documents": len(catalogue["documents"]),
            "serviceSpecifications": sum(
                bool(item.get("serviceCode")) for item in catalogue["documents"]
            ),
            "extractedXmlXsdBlocks": len(extraction["assets"]),
        },
        "documentation": _documentation_audit(),
        "limitations": [
            "Structural metrics do not prove semantic or remote-contour correctness.",
            "JavaScript symbol counts are approximate; ESLint, Jest and the production build are the syntax gates.",
            "Reference-only service profiles intentionally cannot be submitted until service-specific golden/XSD tests pass.",
        ],
    }
    report["gateFailures"] = [
        *report["python"]["parseErrors"],
        *report["serviceContracts"]["integrityFailures"],
    ]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare current audit with checked-in JSON")
    args = parser.parse_args()
    report = build_report()
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != serialized:
            print("{} is stale; run scripts/audit_repository.py".format(_relative(OUTPUT)))
            return 1
        print("Repository audit is current; gateFailures={}".format(len(report["gateFailures"])))
        return 1 if report["gateFailures"] else 0
    OUTPUT.write_text(serialized, encoding="utf-8")
    print("Wrote {} with gateFailures={}".format(_relative(OUTPUT), len(report["gateFailures"])))
    return 1 if report["gateFailures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
