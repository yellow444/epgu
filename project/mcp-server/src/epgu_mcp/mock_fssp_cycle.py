"""Explicit stdio server for the synthetic FSSP demo, not the normal CLI."""
import os
from pathlib import Path
from urllib.parse import urlsplit

from .operations import OperationsAdapter, OperationsConfig, ResultProjection, build_operate_registry
from .server import build_server, load_knowledge

CAPABILITY = 'mock.fssp.60010153.cycle'
RESULT_FIELDS = {'mock_only': bool, 'service': str, 'order_id': int, 'service_final': bool,
                 'document_name': str, 'document_sha256': str, 'document': str}


def mock_server(config):
    parts = urlsplit(config.base_url)
    if parts.hostname != '127.0.0.1' or parts.scheme != 'http' or not config.allow_loopback_http:
        raise ValueError('mock server requires an explicit 127.0.0.1 HTTP backend')
    # Always own the projection, including safe synthetic document bytes.
    config = OperationsConfig(base_url=config.base_url, credential_file=config.credential_file,
        allow_loopback_http=True, timeout=config.timeout, transport=config.transport,
        projections={CAPABILITY: ResultProjection(RESULT_FIELDS, step_references=True)})
    return build_server(build_operate_registry(load_knowledge(), OperationsAdapter(config)))


def main():
    import anyio
    from mcp.server.stdio import stdio_server
    config = OperationsConfig(base_url=os.environ['EPGU_MOCK_BACKEND_URL'],
        credential_file=Path(os.environ['EPGU_MOCK_CREDENTIAL_FILE']), allow_loopback_http=True)
    server = mock_server(config)
    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    anyio.run(run)


if __name__ == '__main__':
    main()
