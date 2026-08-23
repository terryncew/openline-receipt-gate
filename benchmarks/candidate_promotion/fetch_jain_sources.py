from __future__ import annotations

import argparse
import hashlib
import io
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

HERE = Path(__file__).resolve().parent

from jain_xlsx import JainXlsxError, validate_xlsx_container

USER_AGENT = "OpenLine-CPG-001/0.2 (+https://github.com/terryncew/openline-receipt-gate)"
MAX_BYTES = 5_000_000
MAX_ARCHIVE_BYTES = 20_000_000
REQUIRED_FILES = (
    "pnas.1616408114.sd01.xlsx",
    "pnas.1616408114.sd02.xlsx",
    "pnas.1616408114.sd03.xlsx",
)
EUROPE_PMC_ARCHIVE_URL = "https://www.ebi.ac.uk/europepmc/webservices/rest/PMC5293111/supplementaryFiles"
TRUSTED_HOSTS = {
    "www.pnas.org",
    "pnas.org",
    "pmc.ncbi.nlm.nih.gov",
    "pubmed.ncbi.nlm.nih.gov",
    "www.ncbi.nlm.nih.gov",
    "www.ebi.ac.uk",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_source_spec(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else HERE / "JAIN_2017_SOURCE_URLS.json"
    value = json.loads(target.read_text(encoding="utf-8"))
    validate_source_spec(value)
    return value


def validate_source_spec(spec: Mapping[str, Any]) -> None:
    required = set(REQUIRED_FILES)
    if spec.get("schema") != "openline.cpg001.jain_source_urls.v0.2":
        raise ValueError("unsupported_source_url_schema")
    if spec.get("doi") != "10.1073/pnas.1616408114":
        raise ValueError("source_doi_mismatch")
    hosts = spec.get("allowed_hosts")
    if not isinstance(hosts, list) or set(str(value) for value in hosts) != TRUSTED_HOSTS:
        raise ValueError("allowed_hosts_changed")

    archives = spec.get("archive_sources")
    if not isinstance(archives, list) or len(archives) != 1:
        raise ValueError("archive_source_set_mismatch")
    archive = archives[0]
    if archive.get("provider") != "Europe PMC":
        raise ValueError("archive_provider_mismatch")
    if archive.get("authority") != "PMC International archival mirror":
        raise ValueError("archive_authority_mismatch")
    if archive.get("url") != EUROPE_PMC_ARCHIVE_URL or archive.get("format") != "zip":
        raise ValueError("archive_endpoint_mismatch")
    if set(archive.get("required_members", [])) != required:
        raise ValueError("archive_required_members_mismatch")
    parsed_archive = urllib.parse.urlparse(EUROPE_PMC_ARCHIVE_URL)
    if parsed_archive.scheme != "https" or parsed_archive.hostname not in TRUSTED_HOSTS:
        raise ValueError("archive_url_not_allowed")

    artifacts = spec.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != required:
        raise ValueError("source_artifact_set_mismatch")
    for filename, urls in artifacts.items():
        if not isinstance(urls, list) or not urls:
            raise ValueError(f"source_urls_missing:{filename}")
        for url in urls:
            parsed = urllib.parse.urlparse(str(url))
            if parsed.scheme != "https" or parsed.hostname not in TRUSTED_HOSTS:
                raise ValueError(f"source_url_not_allowed:{filename}:{url}")
            if not parsed.path.lower().endswith(filename.lower()):
                raise ValueError(f"source_url_filename_mismatch:{filename}:{url}")


class AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        host = urllib.parse.urlparse(newurl).hostname
        if host not in self.allowed_hosts:
            raise urllib.error.URLError(f"redirect_host_not_allowed:{host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_url(
    url: str,
    allowed_hosts: set[str],
    timeout: float = 30.0,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> tuple[bytes, dict[str, Any]]:
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        AllowlistedRedirectHandler(allowed_hosts),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/zip,application/octet-stream,"
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,*/*;q=0.1"
            ),
        },
    )
    with opener.open(request, timeout=timeout) as response:
        resolved_url = response.geturl()
        final_host = urllib.parse.urlparse(resolved_url).hostname
        if final_host not in allowed_hosts:
            raise ValueError(f"resolved_host_not_allowed:{final_host}")
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if "text/html" in content_type:
            raise ValueError("html_response_rejected")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("source_too_large")
        if not data.startswith(b"PK"):
            raise ValueError("non_zip_magic_rejected")
        return data, {
            "requested_url": url,
            "resolved_url": resolved_url,
            "content_type": content_type,
            "http_status": int(getattr(response, "status", 200)),
        }


def _validate_downloaded_xlsx(filename: str, data: bytes, temp_dir: Path) -> dict[str, Any]:
    if len(data) > MAX_BYTES:
        raise ValueError(f"xlsx_too_large:{filename}")
    probe = temp_dir / (filename + ".probe")
    probe.write_bytes(data)
    try:
        result = validate_xlsx_container(probe)
    except JainXlsxError as exc:
        raise ValueError(str(exc)) from exc
    finally:
        probe.unlink(missing_ok=True)
    return result


def _extract_required_archive_members(data: bytes, temp_dir: Path) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError("archive_not_zip") from exc
    with archive:
        matches: dict[str, bytes] = {}
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = PurePosixPath(info.filename).name
            if name not in REQUIRED_FILES:
                continue
            if name in matches:
                raise ValueError(f"archive_duplicate_member:{name}")
            if info.file_size > MAX_BYTES:
                raise ValueError(f"archive_member_too_large:{name}")
            payload = archive.read(info)
            _validate_downloaded_xlsx(name, payload, temp_dir)
            matches[name] = payload
        missing = [name for name in REQUIRED_FILES if name not in matches]
        if missing:
            raise ValueError("archive_missing_required_members:" + ",".join(missing))
        return matches


def _call_downloader(
    downloader: Callable[..., tuple[bytes, dict[str, Any]]],
    url: str,
    allowed_hosts: set[str],
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, dict[str, Any]]:
    try:
        return downloader(url, allowed_hosts, timeout, max_bytes)
    except TypeError:
        # Backward-compatible hook for frozen unit-test downloaders using the old
        # three-argument signature. Production uses download_url above.
        return downloader(url, allowed_hosts, timeout)


def acquire_sources(
    out_dir: str | Path,
    *,
    spec: Mapping[str, Any] | None = None,
    downloader: Callable[..., tuple[bytes, dict[str, Any]]] = download_url,
    timeout: float = 30.0,
) -> dict[str, Any]:
    source_spec = dict(spec or load_source_spec())
    validate_source_spec(source_spec)
    allowed_hosts = set(str(value) for value in source_spec["allowed_hosts"])
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []

    # Preferred path: one official Europe PMC archival ZIP carrying the exact
    # publisher-named XLSX members. This is an official PMC International source,
    # not a transformed dataset.
    for archive_spec in source_spec["archive_sources"]:
        url = str(archive_spec["url"])
        attempt: dict[str, Any] = {
            "mode": "ARCHIVE",
            "provider": str(archive_spec["provider"]),
            "authority": str(archive_spec["authority"]),
            "url": url,
        }
        try:
            data, meta = _call_downloader(downloader, url, allowed_hosts, timeout, MAX_ARCHIVE_BYTES)
            members = _extract_required_archive_members(data, target)
            artifacts: list[dict[str, Any]] = []
            for filename in REQUIRED_FILES:
                payload = members[filename]
                (target / filename).write_bytes(payload)
                artifacts.append({
                    "filename": filename,
                    "bytes": len(payload),
                    "sha256": sha256_bytes(payload),
                    "source_url": url,
                    "resolved_url": str(meta.get("resolved_url", url)),
                    "archive_member": filename,
                    "source_authority": "EUROPE_PMC_PMC_INTERNATIONAL_ARCHIVE",
                    "content_type": str(meta.get("content_type", "")),
                    "http_status": int(meta.get("http_status", 200)),
                    "xlsx_container_valid": True,
                })
            attempt.update({
                "status": "ACCEPTED",
                "resolved_url": str(meta.get("resolved_url", url)),
                "required_member_count": len(REQUIRED_FILES),
            })
            attempts.append(attempt)
            return _success_receipt(source_spec, artifacts, attempts)
        except (
            OSError,
            ValueError,
            urllib.error.URLError,
            urllib.error.HTTPError,
            socket.timeout,
            zipfile.BadZipFile,
            KeyError,
        ) as exc:
            attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
            attempts.append(attempt)

    # Frozen direct publisher/NCBI paths remain as failover. They are still
    # validated as opaque XLSX containers and hashed before any cells are opened.
    artifacts: list[dict[str, Any]] = []
    for filename, urls in source_spec["artifacts"].items():
        accepted = None
        for url in urls:
            attempt = {"mode": "DIRECT", "filename": filename, "url": url}
            try:
                data, meta = _call_downloader(downloader, str(url), allowed_hosts, timeout, MAX_BYTES)
                _validate_downloaded_xlsx(filename, data, target)
                destination = target / filename
                destination.write_bytes(data)
                accepted = {
                    "filename": filename,
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "source_url": str(url),
                    "resolved_url": str(meta.get("resolved_url", url)),
                    "archive_member": None,
                    "source_authority": "DIRECT_PUBLISHER_OR_NCBI",
                    "content_type": str(meta.get("content_type", "")),
                    "http_status": int(meta.get("http_status", 200)),
                    "xlsx_container_valid": True,
                }
                attempt.update({"status": "ACCEPTED", "resolved_url": accepted["resolved_url"]})
                attempts.append(attempt)
                break
            except (
                OSError,
                ValueError,
                urllib.error.URLError,
                urllib.error.HTTPError,
                socket.timeout,
            ) as exc:
                attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
                attempts.append(attempt)
        if accepted is None:
            for artifact in artifacts:
                (target / artifact["filename"]).unlink(missing_ok=True)
            return {
                "schema": "openline.cpg001.jain_acquisition_receipt.v0.2",
                "experiment_id": "CPG-001",
                "execution_id": "CPG-001-JAIN-EVIDENCE-02",
                "dataset_id": "JAIN_2017",
                "status": "BLOCKED_SOURCE_ACQUISITION",
                "created_at": _now(),
                "failed_filename": filename,
                "artifacts": artifacts,
                "attempts": attempts,
                "processed_mirror_fallback_used": False,
            }
        artifacts.append(accepted)

    return _success_receipt(source_spec, artifacts, attempts)


def _success_receipt(
    source_spec: Mapping[str, Any],
    artifacts: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    stable = {
        "dataset_id": "JAIN_2017",
        "doi": source_spec["doi"],
        "artifacts": [
            {
                k: item[k]
                for k in (
                    "filename",
                    "bytes",
                    "sha256",
                    "source_url",
                    "resolved_url",
                    "archive_member",
                    "source_authority",
                )
            }
            for item in artifacts
        ],
    }
    return {
        "schema": "openline.cpg001.jain_acquisition_receipt.v0.2",
        "experiment_id": "CPG-001",
        "execution_id": "CPG-001-JAIN-EVIDENCE-02",
        "status": "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET",
        "created_at": _now(),
        "source_policy": source_spec["policy"],
        "acquisition_artifact_set_sha256": hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "artifacts": artifacts,
        "attempts": attempts,
        "processed_mirror_fallback_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Acquire exact Jain 2017 XLSX supplements from frozen publisher/PMC archival sources only."
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    receipt = acquire_sources(args.out_dir, timeout=args.timeout)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET" else 2


if __name__ == "__main__":
    raise SystemExit(main())
