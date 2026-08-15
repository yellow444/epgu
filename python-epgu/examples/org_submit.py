"""Пример отправки подготовленного комплекта от имени организации."""

import os
from pathlib import Path

from epgu import TEST, EpguClient, OrderArchive, OrderMeta, validate_xml
from epgu.auth import OrgTokenProvider
from epgu.services import submit_application
from epgu.signature import CryptoProSigner


def main() -> None:
    signer = CryptoProSigner(
        thumbprint=os.environ["EPGU_CERT_THUMBPRINT"],
        pin=os.environ.get("EPGU_KEY_PIN"),
    )
    meta = OrderMeta(
        region=os.environ["EPGU_REGION"],
        service_code=os.environ["EPGU_SERVICE_CODE"],
        target_code=os.environ["EPGU_TARGET_CODE"],
    )

    req_xml = Path(os.environ.get("EPGU_REQ_XML", "req.xml")).read_bytes()
    req_xsd = Path(os.environ.get("EPGU_REQ_XSD", "req.xsd")).read_bytes()
    piev_xml = Path(os.environ.get("EPGU_PIEV_XML", "piev_epgu.xml")).read_bytes()
    validate_xml(req_xml, req_xsd)

    archive = OrderArchive(signer=signer)
    archive.add_file("req.xml", req_xml)
    archive.add_signed_file("piev_epgu.xml", piev_xml)

    with (
        OrgTokenProvider(os.environ["EPGU_API_KEY"], signer, env=TEST) as auth,
        EpguClient(auth, env=TEST) as client,
    ):
        result = submit_application(client, meta, archive, wait=True)
        print("orderId:", result.order_id)
        if result.order is not None:
            print("status:", result.order.status_code, result.order.status_name)


if __name__ == "__main__":
    main()
