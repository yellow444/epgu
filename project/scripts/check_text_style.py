#!/usr/bin/env python3
"""Проверка авторского текста и комментариев без изменения синтаксиса команд.

--fix исправляет найденные фрагменты, --root выбирает другой Git-репозиторий.
Официальные спецификации, лицензии, машинные файлы и тестовые данные
сохраняются. В корневом README разрешены бейджи и символы поддержки проекта.
"""
from __future__ import annotations

import argparse
import ast
import io
from pathlib import Path
import re
import subprocess
import tokenize

BAD = re.compile(r"[\u2012-\u2015\u2190-\u21ff\u2300-\u23ff\u2500-\u257f\u2600-\u27bf\u2b00-\u2bff\U0001f000-\U0001faff\u200b\u200d\u20e3\ufe0f]")
DOUBLE = re.compile(r"(?<=\S)[ \t]+--[ \t]+(?=\S)")
FACE = re.compile(r"(?<![\w/])[:;][\-^]?[)(dDpP](?!\w)")
ARROWS = re.compile(r'[ \t]+(<->|->|=>|<-)[ \t]+')
DECOR = re.compile(r"^([ \t]*(?:\#|//|/\*|\*)[ \t]*)[-=]{3,}[ \t]*|[ \t]*[-=]{3,}(?=[ \t]*(?:\*/)?[ \t]*\n?$)")
COMMAND = re.compile(r"^\s*(?:[#/]\s*)?(?:CI=|\$|python\b|python3\b|pip\b|npm\b|npx\b|node\b|git\b|docker\b|curl\b|pytest\b|pwsh\b|powershell\b)")
GUIDES = {'knowledge.v1.json', 'manual_path.v1.json', 'connection_card.v1.json'}
CODE = {'.py', '.js', '.jsx', '.ts', '.tsx', '.css', '.bsl', '.sh', '.ps1'}
SKIP = ('docs/api_for_gu/', 'api-gosuslugi-backend/xml/', 'node_modules/',
        '/build/', '/dist/', '/release/', 'third_party/', '/vendor/')


def scrub(text: str, comment=False, prose=False) -> str:
    parts = re.split(r'(`[^`\n]*`)', text)
    for i in range(0, len(parts), 2):
        part = parts[i]
        part = re.sub('[\u2012-\u2015]', '-', part)
        part = part.replace('\u2026', '...').replace('\u2022', '-')
        part = part.replace('\u2192', 'затем').replace('\u2190', 'из').replace('\u2194', 'и')
        part = part.replace('\u21d2', 'значит').replace('\u21d0', 'следует из')
        part = FACE.sub('', BAD.sub('', part))
        if not COMMAND.match(part):
            part = DOUBLE.sub(' - ', part)
            if prose:
                words = {'->': 'затем', '<-': 'из', '<->': 'и', '=>': 'означает'}
                part = ARROWS.sub(lambda m: ' ' + words[m.group(1)] + ' ', part)
        if comment:
            cleaned = DECOR.sub(lambda m: m.group(1) or '', part)
            if cleaned != part:
                part = re.sub(r'[ \t]+(?=\n|$)', '', cleaned)
        parts[i] = part
    return ''.join(parts)


def fragments(text: str, path: Path):
    """Вернуть непересекающиеся фрагменты текста: начало, конец и вид комментария."""
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    if path.suffix.lower() == '.md':
        fence = None
        for n, line in enumerate(lines):
            marker = re.match(r'\s*(`{3,}|~{3,})', line)
            if marker:
                if fence is None:
                    fence = marker.group(1)[0]
                elif marker.group(1)[0] == fence:
                    fence = None
                continue
            if fence is None:
                yield offsets[n], offsets[n + 1], False
        return
    if path.name in GUIDES:
        yield 0, len(text), False
        return
    if path.suffix.lower() == '.py':
        tree = ast.parse(text)
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                    docstrings.add((first.value.lineno, first.value.col_offset))
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT or (token.type == tokenize.STRING and token.start in docstrings):
                start = offsets[token.start[0] - 1] + token.start[1]
                end = offsets[token.end[0] - 1] + token.end[1]
                yield start, end, token.type == tokenize.COMMENT
        return
    is_test = '.test.' in path.name or path.name.startswith('test_') or 'tests' in path.parts
    block = False
    for n, line in enumerate(lines):
        stripped = line.lstrip()
        comment = stripped.startswith(('#', '//', '/*')) or block
        if stripped.startswith('/*') and '*/' not in stripped:
            block = True
        if '*/' in stripped:
            block = False
        if comment or (not is_test and path.suffix.lower() in {'.js', '.jsx', '.ts', '.tsx'}):
            yield offsets[n], offsets[n + 1], comment


def process(path: Path, root: Path, fix=False):
    relative = path.relative_to(root).as_posix()
    if relative.lower() == 'readme.md' or path.name == 'check_text_style.py':
        return []
    if any(part in relative for part in SKIP) or 'LICENSE' in path.name or path.name.startswith('NOTICE'):
        return []
    if path.suffix.lower() not in CODE | {'.md'} and path.name not in GUIDES:
        return []
    raw = path.read_bytes()
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return []
    flat = text.replace('\r\n', '\n')
    changes = []
    for start, end, comment in fragments(flat, path):
        original = flat[start:end]
        prose = comment or path.suffix.lower() in {'.md', '.py'} or path.name in GUIDES
        cleaned = scrub(original, comment, prose)
        if cleaned != original:
            changes.append((start, end, cleaned))
    if fix and changes:
        result = flat
        for start, end, cleaned in reversed(changes):
            result = result[:start] + cleaned + result[end:]
        if b'\r\n' in raw:
            result = result.replace('\n', '\r\n')
        path.write_bytes(result.encode('utf-8'))
    return [flat.count('\n', 0, start) + 1 for start, _, _ in changes]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--fix', action='store_true')
    args = parser.parse_args()
    location = (args.root or Path(__file__).resolve().parent).resolve()
    root = Path(subprocess.check_output(['git', '-C', str(location), 'rev-parse', '--show-toplevel'], text=True).strip()).resolve()
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).decode('utf-8').split('\0')
    bad = 0
    for name in sorted(set(names) - {''}):
        path = root / name
        if not path.is_file():
            continue
        rows = process(path, root, args.fix)
        if rows:
            bad += 1
            print(f'{name}: ' + ', '.join(map(str, rows)))
    print(('Исправлено файлов: ' if args.fix else 'Файлов с замечаниями: ') + str(bad))
    return 0 if args.fix or bad == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
