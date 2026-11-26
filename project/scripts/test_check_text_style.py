"""Проверить очистку текста без изменения команд, тестовых данных и Python AST."""
import ast
from pathlib import Path
import tempfile
import unittest

from check_text_style import process


class TextStyleTests(unittest.TestCase):
    def check_file(self, relative, content):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, 'utf-8')
        return root, path

    def test_prose_cleanup_preserves_command_and_diagram_syntax(self):
        content = ('Фраза\u2014пример -- итог \U0001f600\nФорма -> XML\n'
                   '```sh\nnpm test -- --runInBand\n```\n'
                   '```mermaid\na --> b\n```\n'
                   'Флаг `--output`, разделитель `--` и `<!-- comment -->`.\n')
        root, path = self.check_file('docs/guide.md', content)
        self.assertTrue(process(path, root))
        process(path, root, fix=True)
        result = path.read_text('utf-8')
        self.assertIn('npm test -- --runInBand', result)
        self.assertIn('a --> b', result)
        self.assertIn('`<!-- comment -->`', result)
        self.assertNotIn('\U0001f600', result)
        self.assertIn('Форма затем XML', result)
        self.assertFalse(process(path, root))

    def test_comment_cleanup_preserves_python_payload(self):
        content = '# ----- Section -----\nvalue = "\U0001f600"\n'
        root, path = self.check_file('example.py', content)
        before = ast.dump(ast.parse(content))
        self.assertTrue(process(path, root))
        process(path, root, fix=True)
        self.assertEqual(ast.dump(ast.parse(path.read_text('utf-8'))), before)
        self.assertIn('value = "\U0001f600"', path.read_text('utf-8'))

    def test_only_root_readme_allows_marketing_symbols(self):
        root, path = self.check_file('README.md', 'Star \u2b50\n')
        self.assertFalse(process(path, root))
        nested = root / 'docs/README.md'
        nested.parent.mkdir()
        nested.write_text('Text \u2b50', 'utf-8')
        self.assertTrue(process(nested, root))

    def test_fixture_payload_is_not_rewritten(self):
        root, path = self.check_file('example.test.js', 'const payload = "\U0001f600";\n// ---- comment ----\nconst next = 1;\n')
        process(path, root, fix=True)
        self.assertIn('"\U0001f600"', path.read_text('utf-8'))
        self.assertNotIn('----', path.read_text('utf-8'))
        self.assertIn('// comment\nconst next = 1;', path.read_text('utf-8'))

    def test_block_comment_keeps_its_closing_delimiter(self):
        root, path = self.check_file('example.js', '/* ---- Section ---- */\nconst next = 1;\n')
        process(path, root, fix=True)
        self.assertIn('/* Section */\nconst next = 1;', path.read_text('utf-8'))

    def test_javascript_operator_and_html_comment_are_preserved(self):
        root, path = self.check_file('example.js', 'const f = value => value;\n')
        self.assertFalse(process(path, root))
        root, path = self.check_file('docs/template.md', '<!-- Text -->\n')
        self.assertFalse(process(path, root))


if __name__ == '__main__':
    unittest.main()
