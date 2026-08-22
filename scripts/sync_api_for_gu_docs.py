#!/usr/bin/env python3
"""Download and verify the public API Госуслуг documentation snapshot.

The catalogue is a client-rendered page, so the exact links and publication
dates discovered on 2026-08-12 are kept here as reviewable source data.  Every
download is written atomically and recorded with its SHA-256 digest in
``docs/api_for_gu/catalog.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen


SOURCE_PAGE = "https://partners.gosuslugi.ru/catalog/api_for_gu"
SNAPSHOT_DATE = "2026-08-21"
BASE_URL = "https://gu-st.ru/content/partners/api_for_gu/"


def _doc(
    kind: str,
    title: str,
    published: str,
    filename: str,
    code: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    return {
        "kind": kind,
        "serviceCode": code,
        "title": title,
        "published": published,
        "url": BASE_URL + filename,
    }


DOCUMENTS: List[Dict[str, Optional[str]]] = [
    _doc(
        "regulation",
        "Регламент подключения к API Госуслуг, версия 1.8",
        "2026-03-06",
        "Reglament_podklyucheniya_k_API_Gosuslug_1_8.docx",
    ),
    _doc(
        # Публичная редакция без номера версии: на неё ссылается текст
        # каталога, а карточка со ссылкой на 1.8 лежит рядом. Держим обе,
        # чтобы видеть расхождение между тем, что читают снаружи, и тем, по
        # чему мы работаем.
        "regulation",
        "Регламент подключения к API Госуслуг, публичная редакция",
        "",
        "Reglament_podklyucheniya_k_API_Gosuslug.docx",
    ),
    _doc(
        "agreement",
        "Договор присоединения кредитных организаций № 144687вн",
        "2024-12-23",
        "Dogovor_prisoedineniya_k_usloviyam_integracii_kreditnykh_organizacij_k_epgu.pdf",
    ),
    _doc(
        "guide",
        "Руководство организации-вендора по API-Key, версия 3.2",
        "2022-10-26",
        "Rukovodstvo_polzovatelya_dlya_organizacii-vendora_po_formirovaniyu_API-Key_i_polucheniyu_markera_dostupa._Versiya_3.2_ot_26.10.2022_g..pdf",
    ),
    _doc(
        "guide",
        "Руководство организации-потребителя по API-Key, версия 3.3",
        "2023-01-31",
        "Rukovodstvo_polzovatelya_dlya_organizacii-potrebitelya_po_formirovaniyu_API-Key_i_polucheniyu_markera_dostupa._Versiya_3.3_ot_31.01.2023_g.docx",
    ),
    _doc(
        "guide",
        "Инструкция по взаимодействию с Личным кабинетом API ЕПГУ",
        "",
        "Instrukciya_LK_API_v1.docx",
    ),
    _doc(
        "core-specification",
        "Спецификация API ЕПГУ, версия 1.14",
        "2026-01-29",
        "Specifikaciya_API_EPGU_v1_14.docx",
    ),
    _doc(
        "service-specification",
        "Отправка документов на подпись в Госключ",
        "2025-08-28",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000374_v1.9.docx",
        "10000000374",
    ),
    _doc(
        "service-specification",
        "Предоставление информации о ходе исполнительного производства онлайн",
        "2025-09-24",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000352_Hod_IP_v9.docx",
        "10000000352",
    ),
    _doc(
        "service-specification",
        "Предоставление информации о наличии исполнительного производства онлайн",
        "2024-07-17",
        "Specifikaciya_API_EPGU_Prilozhenie_60010153_Nalichie_IP_v8.docx",
        "60010153",
    ),
    _doc(
        "service-specification",
        "Подача заявлений, ходатайств, объяснений, отводов и жалоб по исполнительному производству",
        "2026-03-31",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000367_Podacha_zayavleni_hodatajstv_obyasnenij_v1.4.docx",
        "10000000367",
    ),
    _doc(
        "service-specification",
        "Информация об исполнительных производствах для снятия ограничений на выезд",
        "2024-07-18",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000396_servis_snyatiya_ogranichenij_na_vyezd_v1.docx",
        "10000000396",
    ),
    _doc(
        "service-specification",
        "Приём заявлений о доставке пенсий и иных социальных выплат",
        "2024-11-15",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000109_Priem_zayavlenij_o_dostavke_pensij_i_inykh_socialnykh_vyplat_v1.1.docx",
        "10000000109",
    ),
    _doc(
        "service-specification",
        "Назначение страховых и накопительных пенсий (600110_1)",
        "2025-05-29",
        "Specifikaciya_API_EPGU_Prilozhenie_10000000110_Naznachenie_pensii_v1.1.docx",
        "10000000110",
    ),
    _doc(
        "service-specification",
        "Приём заявлений о доставке пенсии и иных социальных выплат",
        "2025-01-17",
        "Specifikaciya_API_EPGU_Prilozhenie_60013502_Priem_zayavlenij_o_dostavke_pensij_i_inykh_socialnykh_vyplat_v1.2.docx",
        "60013502",
    ),
    _doc(
        "service-specification",
        "Корректировка сведений индивидуального лицевого счёта",
        "2024-12-20",
        "Specifikaciya_API_EPGU_Prilozhenie_613730_Priem_ot_zastrakhovannykh_lic_zayavlenij_o_korrektirovke_svedenij_ILS_v1.3.docx",
        "60013730",
    ),
    _doc(
        "service-specification",
        "Назначение страховых и накопительных пенсий",
        "2024-09-19",
        "Specifikaciya_API_EPGU_Prilozhenie_60019724_Naznachenie_pensii_v1.3.docx",
        "60019724",
    ),
    _doc(
        "service-specification",
        "Уведомления о трудовых договорах с иностранными гражданами",
        "2024-08-15",
        "Specifikaciya_API_EPGU_Uvedomlenie_o_trudovoj_deyatelnosti_1.3.docx",
        "10000000585",
    ),
    _doc(
        "service-specification",
        "Поиск иностранного гражданина в реестре контролируемых лиц",
        "2025-03-06",
        "Specification_API_EPGU_Search_for_foreigner_in_RKL_V_1.3.docx",
        "60057731",
    ),
    _doc(
        "service-specification",
        "Подписание документов УКЭП юридическими лицами",
        "2025-08-28",
        "Specifikaciya_API_EPGU_Prilozhenie_60025907.docx",
        "60025907",
    ),
    _doc(
        "service-specification",
        "Обмен сведениями с реестром организаторов распространения информации",
        "2025-12-03",
        "Specifikaciya_TOT_03_12_2025.docx",
        "60048912",
    ),
    _doc(
        "protocol-specification",
        "Спецификация API ГЭПС, версия 1.0",
        "2026-01-29",
        "Specifikaciya_API_GEPS_v1.0.docx",
    ),
    _doc(
        "service-specification",
        "Уведомления медицинских организаций о регистрации граждан",
        "2026-04-20",
        "Specifikaciya_API_EPGU_Servisy_uvedomleniya_ot_medicinskih_organizatsiy_o_registracii_grazhdan_v1.0.docx",
        "60078836",
    ),
    _doc(
        "service-specification",
        "Регистрация транспортных средств",
        "2026-03-17",
        "Spetsifikatsiya_API_EPGU_Prilozhenie_10000000804_RegistratsiyaTS_v1.docx",
        "10000000804",
    ),
    _doc(
        "service-specification",
        "Подача обращений в органы прокуратуры",
        "2026-03-03",
        "Specification_API_EPGU_Submission_of_appeals_to_the_prosecutors.docx",
        "60011906",
    ),
    _doc(
        "service-specification",
        "Ежегодная семейная выплата",
        "2026-06-04",
        "Specifikaciya_API_EPGU_Prilozhenie_680315_Family_v1.0_%20editing_the_directory_SFR_CO_01.docx",
        "60080315",
    ),
    _doc(
        "service-specification",
        "Миграционный и регистрационный учёт для гостиниц",
        "2026-06-22",
        "Specifikaciya_API_EPGU_Servisy_migracionnogo_i_registracionnogo_uchyotov_dlya_gostinic_v3.0_600588.docx",
        "10000000588",
    ),
    _doc(
        "service-specification",
        "Расшифрование документов в Госключе",
        "2025-11-01",
        "Specifikaciya_API_EPGU_Prilozhenie_60079416_.docx",
        "60079416",
    ),
    _doc(
        "service-specification",
        "Подписание УКЭП с сертификатом Федерального казначейства",
        "2026-02-25",
        "Specifikaciya_API_EPGU_Prilozhenie_ukep_roskazna.docx",
        "60080470",
    ),
]


def _local_name(item: Dict[str, Optional[str]]) -> str:
    basename = unquote(Path(urlsplit(str(item["url"])).path).name)
    basename = basename.replace("%20", "_").replace(" ", "_")
    if item.get("serviceCode") and not basename.startswith(str(item["serviceCode"])):
        return "{}__{}".format(item["serviceCode"], basename)
    return basename


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_file(path: Path, expected_suffix: Optional[str] = None) -> None:
    with path.open("rb") as stream:
        magic = stream.read(8)
    suffix = (expected_suffix or path.suffix).lower()
    if suffix == ".docx" and not magic.startswith(b"PK"):
        raise ValueError("{} is not an OOXML ZIP file".format(path))
    if suffix == ".pdf" and not magic.startswith(b"%PDF"):
        raise ValueError("{} is not a PDF file".format(path))


def _download(url: str, destination: Path, attempts: int = 3) -> None:
    request = Request(
        url,
        headers={
            "User-Agent": "epgu-api-doc-sync/1.0 (+https://github.com/yellow444/epgu)",
            "Accept": "application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,*/*",
        },
    )
    temporary = destination.with_suffix(destination.suffix + ".part")
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            with urlopen(request, timeout=90) as response, temporary.open("wb") as output:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    output.write(block)
            if temporary.stat().st_size == 0:
                raise ValueError("empty response")
            _validate_file(temporary, destination.suffix)
            os.replace(str(temporary), str(destination))
            return
        except Exception as exc:  # network failures differ between Python versions
            last_error = exc
            if temporary.exists():
                temporary.unlink()
            if attempt < attempts:
                time.sleep(attempt)
    raise RuntimeError("failed to download {}: {}".format(url, last_error))


def _write_manifest(root: Path, entries: Iterable[Dict[str, object]]) -> Path:
    manifest = {
        "schemaVersion": 1,
        "sourcePage": SOURCE_PAGE,
        "catalogObservedAt": SNAPSHOT_DATE,
        "documents": list(entries),
    }
    path = root / "catalog.json"
    temporary = path.with_suffix(".json.part")
    temporary.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(str(temporary), str(path))
    return path


def sync(root: Path, force: bool) -> int:
    source_dir = root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, object]] = []
    for index, item in enumerate(DOCUMENTS, 1):
        name = _local_name(item)
        destination = source_dir / name
        if force or not destination.exists():
            print("[{}/{}] {}".format(index, len(DOCUMENTS), name), flush=True)
            _download(str(item["url"]), destination)
        _validate_file(destination)
        record: Dict[str, object] = dict(item)
        record.update(
            {
                "file": "source/{}".format(name),
                "bytes": destination.stat().st_size,
                "sha256": _sha256(destination),
            }
        )
        records.append(record)
    manifest = _write_manifest(root, records)
    print("Wrote {} ({} documents)".format(manifest, len(records)))
    return 0


def check(root: Path) -> int:
    manifest_path = root / "catalog.json"
    if not manifest_path.exists():
        print("Missing {}".format(manifest_path), file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures = 0
    for item in manifest.get("documents", []):
        path = root / item["file"]
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                _download(str(item["url"]), path)
            except Exception as exc:
                print("DOWNLOAD {}: {}".format(path, exc), file=sys.stderr)
                failures += 1
                continue
        try:
            _validate_file(path)
        except ValueError as exc:
            print("FORMAT {}: {}".format(path, exc), file=sys.stderr)
            failures += 1
            continue
        actual = _sha256(path)
        if actual != item.get("sha256"):
            print("HASH {}: {} != {}".format(path, actual, item.get("sha256")), file=sys.stderr)
            failures += 1
    print("Verified {} documents; failures={}".format(len(manifest.get("documents", [])), failures))
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="download missing local files and verify them against the recorded manifest",
    )
    parser.add_argument("--force", action="store_true", help="download every document again")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "docs" / "api_for_gu",
    )
    args = parser.parse_args()
    return check(args.output) if args.check else sync(args.output, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
