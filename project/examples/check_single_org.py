"""Install public dependencies in a fresh venv and run one-organization mocks.

Run from any directory. No private overlay, Docker, CSP, EPGU credentials or
real service connection. pip needs access to the configured package index.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import venv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory outside Git and existing installations')
    args = parser.parse_args()
    output = args.output.resolve()
    if any((p / '.git').exists() for p in (output, *output.parents)):
        parser.error('output must be outside Git')
    if output.exists() and any(output.iterdir()):
        parser.error('output must be empty')
    project = Path(__file__).resolve().parents[1]
    output.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    for key in ('PYTHONPATH', 'PYTHONHOME'):
        environment.pop(key, None)
    environment.update(PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1',
                       PYTHON_DOTENV_DISABLED='1', PIP_DISABLE_PIP_VERSION_CHECK='1',
                       TMP=str(output), TEMP=str(output), TMPDIR=str(output))
    venv_path = output / 'venv'
    venv.EnvBuilder(with_pip=True).create(venv_path)
    python = venv_path / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    # requirements.txt contains editable sibling paths; its cwd is intentional.
    with (output / 'install.log').open('wb') as log:
        result = subprocess.run([str(python), '-m', 'pip', 'install', '-r', 'requirements.txt',
            '-e', '../mcp-server[operations]'], cwd=project / 'api-gosuslugi-backend',
            env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        raise SystemExit('Dependency installation failed; see ' + str(output / 'install.log'))
    with (output / 'cycle.log').open('wb') as log:
        result = subprocess.run([str(python), str(project / 'examples/fssp_mock_cycle.py'),
            '--output', str(output / 'cycle')], cwd=output, env=environment,
            stdout=log, stderr=subprocess.STDOUT, timeout=180)
    if result.returncode:
        raise SystemExit('Mock cycle failed; see ' + str(output / 'cycle.log'))
    receipt = json.loads((output / 'cycle/receipt.json').read_text('utf-8'))
    assert receipt['mock_only'] and not receipt['private_addons_installed']
    assert receipt['backend_stopped'] and receipt['credential_removed'] and receipt['integration_revoked']
    assert set(receipt['runs']) == {'http', 'mcp'}
    assert all(run['status'] == 'succeeded' and run['upstream_calls'] ==
               ['reserve', 'push', 'status', 'download'] for run in receipt['runs'].values())
    summary = {'mock_only': True, 'private_addons_required': False, 'organizations': 1,
               'http_cycle': 'succeeded', 'mcp_cycle': 'succeeded',
               'temporary_integration_revoked': True, 'backend_stopped': True,
               'receipt': 'cycle/receipt.json'}
    (output / 'single-org-check.json').write_text(json.dumps(summary, indent=2) + '\n', 'utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
