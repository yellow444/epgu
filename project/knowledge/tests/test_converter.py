import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "convert_guide.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node не найден")

GUIDE = """\
export const REVIEWED_AT = '2026-01-01';
export const SOURCES = {
  a: { title: 'T', url: 'https://example.org/a', kind: '%s', section: 'S' },
};
const e = (to, label) => ({ to, label });
export const FLOWS = [
  { id: 'esia', title: 'R', summary: 'S', nodes: [
    { id: 'start', title: 'N', column: 1, row: 0, body: 'B', checks: [],
      sources: ['a'], next: [e('start', 'loop')], warning: '' },
  ] },
];
export const PRACTICAL_NOTES = [{ title: 'n', status: 's', text: 't', sources: ['a'] }];
"""


def run(src, out):
    return subprocess.run([NODE, "--no-warnings", str(TOOL), str(src), str(out)],
                          capture_output=True, text=True, encoding="utf-8")


def test_converter_deterministic_and_maps(tmp_path):
    src = tmp_path / "guideData.mjs"
    src.write_text(GUIDE % "Официальный FAQ", encoding="utf-8")
    out1, out2 = tmp_path / "1.json", tmp_path / "2.json"
    assert run(src, out1).returncode == 0
    assert run(src, out2).returncode == 0
    assert out1.read_bytes() == out2.read_bytes()
    assert out1.read_bytes().endswith(b"}\n")
    data = json.loads(out1.read_text(encoding="utf-8"))
    assert data["sources"][0]["officiality"] == "official_catalog"
    assert data["routes"][0]["nodes"][0]["warning"] is None
    assert data["dataset"]["generated_from"]["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()


def test_converter_rejects_unknown_kind(tmp_path):
    src = tmp_path / "guideData.mjs"
    src.write_text(GUIDE % "Какой-то новый вид", encoding="utf-8")
    res = run(src, tmp_path / "out.json")
    assert res.returncode == 1
    assert "unknown source kind" in res.stderr
    assert not (tmp_path / "out.json").exists()
