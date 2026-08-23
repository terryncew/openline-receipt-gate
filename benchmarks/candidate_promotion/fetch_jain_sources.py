from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
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

USER_AGENT = "OpenLine-CPG-001/0.4 (+https://github.com/terryncew/openline-receipt-gate)"
MAX_BYTES = 5_000_000
MAX_ARCHIVE_BYTES = 20_000_000
MAX_JSON_BYTES = 1_000_000
REQUIRED_FILES = (
    "pnas.1616408114.sd01.xlsx",
    "pnas.1616408114.sd02.xlsx",
    "pnas.1616408114.sd03.xlsx",
)
EUROPE_PMC_ARCHIVE_URL = "https://www.ebi.ac.uk/europepmc/webservices/rest/PMC5293111/supplementaryFiles"
BIOSTUDIES_ACCESSION = "S-EPMC5293111"
BIOSTUDIES_INFO_URL = "https://www.ebi.ac.uk/biostudies/api/v1/studies/S-EPMC5293111/info"
TRUSTED_HOSTS = {
    "www.pnas.org",
    "pnas.org",
    "pmc.ncbi.nlm.nih.gov",
    "pubmed.ncbi.nlm.nih.gov",
    "www.ncbi.nlm.nih.gov",
    "www.ebi.ac.uk",
    "ftp.ebi.ac.uk",
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
    if spec.get("schema") != "openline.cpg001.jain_source_urls.v0.4":
        raise ValueError("unsupported_source_url_schema")
    if spec.get("doi") != "10.1073/pnas.1616408114":
        raise ValueError("source_doi_mismatch")
    hosts = spec.get("allowed_hosts")
    if not isinstance(hosts, list) or set(str(value) for value in hosts) != TRUSTED_HOSTS:
        raise ValueError("allowed_hosts_changed")

    biostudies = spec.get("biostudies_source")
    if not isinstance(biostudies, Mapping):
        raise ValueError("biostudies_source_missing")
    if biostudies.get("provider") != "EMBL-EBI BioStudies":
        raise ValueError("biostudies_provider_mismatch")
    if biostudies.get("authority") != "S-EPMC Europe PMC supplementary-data import":
        raise ValueError("biostudies_authority_mismatch")
    if biostudies.get("accession") != BIOSTUDIES_ACCESSION:
        raise ValueError("biostudies_accession_mismatch")
    if biostudies.get("info_url") != BIOSTUDIES_INFO_URL:
        raise ValueError("biostudies_info_url_mismatch")
    if biostudies.get("file_host") != "ftp.ebi.ac.uk":
        raise ValueError("biostudies_file_host_mismatch")
    if set(biostudies.get("required_files", [])) != required:
        raise ValueError("biostudies_required_files_mismatch")
    public_bases = biostudies.get("public_file_bases")
    expected_public_bases = {
        "https://www.ebi.ac.uk/biostudies/files/S-EPMC5293111",
        "https://www.ebi.ac.uk/biostudies/files/S-EPMC5293111/Files",
        "https://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/111/S-EPMC5293111/Files",
        "https://ftp.ebi.ac.uk/biostudies/nfs/S-EPMC/111/S-EPMC5293111/Files",
        "https://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/S-EPMCxxx111/S-EPMC5293111/Files",
        "https://ftp.ebi.ac.uk/biostudies/nfs/S-EPMC/S-EPMCxxx111/S-EPMC5293111/Files",
    }
    if not isinstance(public_bases, list) or set(str(v).rstrip("/") for v in public_bases) != expected_public_bases:
        raise ValueError("biostudies_public_file_bases_changed")
    for base in public_bases:
        parsed = urllib.parse.urlparse(str(base))
        if parsed.scheme != "https" or parsed.hostname not in TRUSTED_HOSTS:
            raise ValueError(f"biostudies_public_base_not_allowed:{base}")

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


def _opener(allowed_hosts: set[str]) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        AllowlistedRedirectHandler(allowed_hosts),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def download_json_url(
    url: str,
    allowed_hosts: set[str],
    timeout: float = 30.0,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json,*/*;q=0.1"},
    )
    with _opener(allowed_hosts).open(request, timeout=timeout) as response:
        resolved_url = response.geturl()
        final_host = urllib.parse.urlparse(resolved_url).hostname
        if final_host not in allowed_hosts:
            raise ValueError(f"resolved_host_not_allowed:{final_host}")
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if "text/html" in content_type:
            raise ValueError("html_response_rejected")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("json_source_too_large")
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("json_response_invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("json_response_not_object")
        return value, {
            "requested_url": url,
            "resolved_url": resolved_url,
            "content_type": content_type,
            "http_status": int(getattr(response, "status", 200)),
        }


def download_url(
    url: str,
    allowed_hosts: set[str],
    timeout: float = 30.0,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> tuple[bytes, dict[str, Any]]:
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
    with _opener(allowed_hosts).open(request, timeout=timeout) as response:
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
        return downloader(url, allowed_hosts, timeout)


def _call_json_downloader(
    downloader: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
    url: str,
    allowed_hosts: set[str],
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        return downloader(url, allowed_hosts, timeout, MAX_JSON_BYTES)
    except TypeError:
        return downloader(url, allowed_hosts, timeout)


def _biostudies_https_base(info: Mapping[str, Any], accession: str) -> tuple[str, str]:
    rel_path = str(info.get("relPath", "")).strip().strip("/")
    ftp_link = str(info.get("ftpLink", "")).strip()
    if not rel_path or not rel_path.endswith("/" + accession) and rel_path != accession:
        raise ValueError("biostudies_relpath_invalid")
    if not rel_path.startswith("S-EPMC/"):
        raise ValueError("biostudies_relpath_collection_mismatch")
    if not ftp_link:
        raise ValueError("biostudies_ftplink_missing")
    parsed = urllib.parse.urlparse(ftp_link)
    if parsed.hostname != "ftp.ebi.ac.uk":
        raise ValueError("biostudies_ftplink_host_mismatch")
    path = parsed.path.rstrip("/")
    expected_tail = "/" + rel_path
    if not path.endswith(expected_tail):
        raise ValueError("biostudies_ftplink_relpath_mismatch")
    if not path.startswith("/biostudies/fire/") and not path.startswith("/biostudies/nfs/"):
        raise ValueError("biostudies_storage_mode_invalid")
    return "https://ftp.ebi.ac.uk" + path, rel_path


def _acquire_biostudies_public_files(
    target: Path,
    source_spec: Mapping[str, Any],
    allowed_hosts: set[str],
    *,
    downloader: Callable[..., tuple[bytes, dict[str, Any]]],
    timeout: float,
    attempts: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    spec = source_spec["biostudies_source"]
    accession = str(spec["accession"])
    for raw_base in spec["public_file_bases"]:
        base = str(raw_base).rstrip("/")
        staged: list[tuple[str, bytes, dict[str, Any], str]] = []
        family_attempts: list[dict[str, Any]] = []
        family_ok = True
        for filename in REQUIRED_FILES:
            url = base + "/" + urllib.parse.quote(filename, safe="")
            attempt: dict[str, Any] = {
                "mode": "BIOSTUDIES_PUBLIC_FILE",
                "accession": accession,
                "filename": filename,
                "base_url": base,
                "url": url,
            }
            try:
                data, meta = _call_downloader(downloader, url, allowed_hosts, timeout, MAX_BYTES)
                _validate_downloaded_xlsx(filename, data, target)
                attempt.update({
                    "status": "ACCEPTED",
                    "resolved_url": str(meta.get("resolved_url", url)),
                })
                staged.append((filename, data, meta, url))
            except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as exc:
                attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
                family_ok = False
            family_attempts.append(attempt)
            if not family_ok:
                break
        attempts.extend(family_attempts)
        if not family_ok or len(staged) != len(REQUIRED_FILES):
            continue
        artifacts: list[dict[str, Any]] = []
        for filename, data, meta, url in staged:
            destination = target / filename
            destination.write_bytes(data)
            artifacts.append({
                "filename": filename,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "source_url": url,
                "resolved_url": str(meta.get("resolved_url", url)),
                "archive_member": None,
                "source_authority": "EMBL_EBI_BIOSTUDIES_PUBLIC_FILE",
                "biostudies_accession": accession,
                "content_type": str(meta.get("content_type", "")),
                "http_status": int(meta.get("http_status", 200)),
                "xlsx_container_valid": True,
            })
        return artifacts
    return None


def _acquire_biostudies(
    target: Path,
    source_spec: Mapping[str, Any],
    allowed_hosts: set[str],
    *,
    downloader: Callable[..., tuple[bytes, dict[str, Any]]],
    json_downloader: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
    timeout: float,
    attempts: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    spec = source_spec["biostudies_source"]
    accession = str(spec["accession"])
    info_url = str(spec["info_url"])
    info_attempt: dict[str, Any] = {
        "mode": "BIOSTUDIES_INFO",
        "provider": str(spec["provider"]),
        "authority": str(spec["authority"]),
        "accession": accession,
        "url": info_url,
    }
    try:
        info, meta = _call_json_downloader(json_downloader, info_url, allowed_hosts, timeout)
        base_url, rel_path = _biostudies_https_base(info, accession)
        info_attempt.update({
            "status": "ACCEPTED",
            "resolved_url": str(meta.get("resolved_url", info_url)),
            "rel_path": rel_path,
        })
        attempts.append(info_attempt)
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, socket.timeout, KeyError) as exc:
        info_attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
        attempts.append(info_attempt)
        return None

    artifacts: list[dict[str, Any]] = []
    created: list[Path] = []
    try:
        for filename in REQUIRED_FILES:
            url = base_url + "/Files/" + urllib.parse.quote(filename, safe="")
            attempt: dict[str, Any] = {
                "mode": "BIOSTUDIES_FILE",
                "accession": accession,
                "filename": filename,
                "url": url,
            }
            try:
                data, meta = _call_downloader(downloader, url, allowed_hosts, timeout, MAX_BYTES)
                _validate_downloaded_xlsx(filename, data, target)
                destination = target / filename
                destination.write_bytes(data)
                created.append(destination)
                artifact = {
                    "filename": filename,
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "source_url": url,
                    "resolved_url": str(meta.get("resolved_url", url)),
                    "archive_member": None,
                    "source_authority": "EMBL_EBI_BIOSTUDIES_S_EPMC_IMPORT",
                    "biostudies_accession": accession,
                    "content_type": str(meta.get("content_type", "")),
                    "http_status": int(meta.get("http_status", 200)),
                    "xlsx_container_valid": True,
                }
                artifacts.append(artifact)
                attempt.update({"status": "ACCEPTED", "resolved_url": artifact["resolved_url"]})
                attempts.append(attempt)
            except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as exc:
                attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
                attempts.append(attempt)
                raise
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, socket.timeout):
        for path in created:
            path.unlink(missing_ok=True)
        return None
    return artifacts


def acquire_sources(
    out_dir: str | Path,
    *,
    spec: Mapping[str, Any] | None = None,
    downloader: Callable[..., tuple[bytes, dict[str, Any]]] = download_url,
    json_downloader: Callable[..., tuple[dict[str, Any], dict[str, Any]]] = download_json_url,
    timeout: float = 30.0,
    prefer_biostudies: bool = False,
    execution_id: str = "CPG-001-JAIN-EVIDENCE-02",
) -> dict[str, Any]:
    source_spec = dict(spec or load_source_spec())
    validate_source_spec(source_spec)
    allowed_hosts = set(str(value) for value in source_spec["allowed_hosts"])
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []

    if prefer_biostudies:
        # Execution 04 adds the documented public-file/static transport family.
        # Older execution IDs retain their original acquisition semantics so their
        # frozen regression tests remain a faithful record of those runs.
        if execution_id == "CPG-001-JAIN-EVIDENCE-04":
            artifacts = _acquire_biostudies_public_files(
                target,
                source_spec,
                allowed_hosts,
                downloader=downloader,
                timeout=timeout,
                attempts=attempts,
            )
            if artifacts is not None:
                return _success_receipt(source_spec, artifacts, attempts, execution_id)
        artifacts = _acquire_biostudies(
            target,
            source_spec,
            allowed_hosts,
            downloader=downloader,
            json_downloader=json_downloader,
            timeout=timeout,
            attempts=attempts,
        )
        if artifacts is not None:
            return _success_receipt(source_spec, artifacts, attempts, execution_id)

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
            artifacts = []
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
            return _success_receipt(source_spec, artifacts, attempts, execution_id)
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

    artifacts = []
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
            except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as exc:
                attempt.update({"status": "REJECTED", "reason": f"{type(exc).__name__}:{exc}"})
                attempts.append(attempt)
        if accepted is None:
            for artifact in artifacts:
                (target / artifact["filename"]).unlink(missing_ok=True)
            return {
                "schema": "openline.cpg001.jain_acquisition_receipt.v0.4",
                "experiment_id": "CPG-001",
                "execution_id": execution_id,
                "dataset_id": "JAIN_2017",
                "status": "BLOCKED_SOURCE_ACQUISITION",
                "created_at": _now(),
                "failed_filename": filename,
                "artifacts": artifacts,
                "attempts": attempts,
                "processed_mirror_fallback_used": False,
            }
        artifacts.append(accepted)

    return _success_receipt(source_spec, artifacts, attempts, execution_id)


def _success_receipt(
    source_spec: Mapping[str, Any],
    artifacts: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    execution_id: str,
) -> dict[str, Any]:
    stable_artifacts = []
    for item in artifacts:
        stable_artifacts.append({
            key: item.get(key)
            for key in (
                "filename",
                "bytes",
                "sha256",
                "source_url",
                "resolved_url",
                "archive_member",
                "source_authority",
                "biostudies_accession",
            )
        })
    stable = {"dataset_id": "JAIN_2017", "doi": source_spec["doi"], "artifacts": stable_artifacts}
    return {
        "schema": "openline.cpg001.jain_acquisition_receipt.v0.4",
        "experiment_id": "CPG-001",
        "execution_id": execution_id,
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
        description="Acquire exact Jain 2017 XLSX supplements from frozen publisher/official archival sources only."
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--prefer-biostudies", action="store_true")
    args = parser.parse_args()
    execution_id = os.environ.get("CPG_EXECUTION_ID", "CPG-001-JAIN-EVIDENCE-04")
    receipt = acquire_sources(
        args.out_dir,
        timeout=args.timeout,
        prefer_biostudies=args.prefer_biostudies,
        execution_id=execution_id,
    )
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET" else 2


if __name__ == "__main__":
    raise SystemExit(main())
