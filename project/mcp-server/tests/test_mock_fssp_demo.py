"""The opt-in mock server must not change standard profiles or accept remote backends."""
import pytest
from epgu_mcp.mock_fssp_cycle import CAPABILITY, RESULT_FIELDS, mock_server
from epgu_mcp.operations import OperationsConfig
from epgu_mcp.server import build_registry, load_knowledge


@pytest.mark.parametrize('url',['https://example.invalid','http://localhost:55000','https://127.0.0.1:55000'])
def test_mock_entrypoint_refuses_other_backend_origins(tmp_path,url):
    config=OperationsConfig(base_url=url,credential_file=(tmp_path/'nonexistent').resolve(),
                            allow_loopback_http=True)
    with pytest.raises(ValueError,match='127.0.0.1'):
        mock_server(config)


def test_importing_demo_does_not_enable_operations_in_standard_registry():
    names=set(build_registry('knowledge',load_knowledge()).names())
    assert len(names)==11
    assert not {'plan_prepare','plan_get','plan_execute','plan_approve'}&names
    assert CAPABILITY=='mock.fssp.60010153.cycle'
    assert set(RESULT_FIELDS)=={'mock_only','service','order_id','service_final',
                                'document_name','document_sha256','document'}
