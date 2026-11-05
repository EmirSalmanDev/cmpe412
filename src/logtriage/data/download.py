"""Download of the AIT datasets from Zenodo and selective extraction (plan 4.2, M1)."""

import hashlib
import http.client
import json
import logging
import shutil
import ssl
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import certifi

from logtriage.config import (
    DownloadConfig,
    LogSources,
    Settings,
    SourceConfig,
    glob_match,
    load_sources,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")
USER_AGENT = "logtriage-downloader"
RETRYABLE_ERRORS = (
    urllib.error.URLError,
    http.client.HTTPException,
    TimeoutError,
    ConnectionError,
)


class ChecksumError(RuntimeError):
    """A downloaded file does not match the checksum published by Zenodo."""


class InsufficientDiskError(RuntimeError):
    """There is not enough free disk space for a download or an extraction."""


@dataclass(frozen=True)
class RemoteFile:
    """A file published in a Zenodo record."""

    name: str
    size: int
    md5: str
    url: str


def parse_record(record: dict[str, Any]) -> dict[str, RemoteFile]:
    """Parse a Zenodo record API response into its files, keyed by file name.

    Args:
        record: Decoded JSON from `GET /api/records/<id>`.

    Returns:
        File name to `RemoteFile`.

    Raises:
        ValueError: If a file does not carry an MD5 checksum.
    """
    files: dict[str, RemoteFile] = {}
    for entry in record["files"]:
        algorithm, _, digest = entry["checksum"].partition(":")
        if algorithm != "md5" or not digest:
            raise ValueError(f"{entry['key']}: expected an md5 checksum, got {entry['checksum']!r}")
        files[entry["key"]] = RemoteFile(
            name=entry["key"], size=entry["size"], md5=digest, url=entry["links"]["self"]
        )
    return files


def select_remote_files(
    available: dict[str, RemoteFile], wanted: Iterable[str]
) -> list[RemoteFile]:
    """Pick the wanted files from a record, failing if one is not published."""
    wanted = list(wanted)
    missing = sorted(set(wanted) - set(available))
    if missing:
        raise KeyError(f"not in Zenodo record: {missing}; available: {sorted(available)}")
    return [available[name] for name in wanted]


def md5_file(path: Path, chunk_bytes: int = 8 * 1024 * 1024) -> str:
    """Return the hex MD5 of a file, read in chunks."""
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_bytes):
            digest.update(chunk)
    return digest.hexdigest()


def is_valid_download(path: Path, remote: RemoteFile, chunk_bytes: int = 8 * 1024 * 1024) -> bool:
    """Return True if `path` exists and matches the published size and MD5."""
    if not path.is_file() or path.stat().st_size != remote.size:
        return False
    return md5_file(path, chunk_bytes) == remote.md5


def require_free_space(directory: Path, needed_bytes: int) -> None:
    """Raise `InsufficientDiskError` unless `directory` has `needed_bytes` free."""
    free = shutil.disk_usage(directory).free
    if free < needed_bytes:
        raise InsufficientDiskError(
            f"{directory}: {needed_bytes / 1e9:.1f} GB needed, {free / 1e9:.1f} GB free"
        )


def with_retries(
    action: Callable[[], T],
    max_retries: int,
    backoff_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run `action`, retrying network errors with exponential backoff.

    Args:
        action: The operation to run.
        max_retries: Retries after the first attempt.
        backoff_seconds: Delay before the first retry; it doubles each retry.
        sleep: Delay function, replaceable in tests.

    Returns:
        The result of `action`.
    """
    for attempt in range(max_retries + 1):
        try:
            return action()
        except RETRYABLE_ERRORS as error:
            permanent = isinstance(getattr(error, "reason", None), ssl.SSLCertVerificationError)
            if permanent or attempt == max_retries:
                raise
            delay = backoff_seconds * 2**attempt
            logger.warning("attempt %d failed (%s); retrying in %.0fs", attempt + 1, error, delay)
            sleep(delay)
    raise AssertionError("unreachable")


def _open_url(url: str, timeout: float, offset: int = 0) -> Any:
    """Open a URL, asking for the bytes from `offset` onwards."""
    headers = {"User-Agent": USER_AGENT}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    # Some Python builds ship without a CA store, so verify against certifi's bundle.
    context = ssl.create_default_context(cafile=certifi.where())
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=timeout, context=context)


def fetch_record(record_id: int, config: DownloadConfig) -> dict[str, RemoteFile]:
    """Fetch and parse a Zenodo record."""

    def fetch() -> dict[str, Any]:
        url = f"{config.api_url}/{record_id}"
        with _open_url(url, config.timeout_seconds) as response:
            return json.load(response)

    return parse_record(with_retries(fetch, config.max_retries, config.backoff_seconds))


def _stream_to_part(remote: RemoteFile, part: Path, config: DownloadConfig) -> None:
    """Download into `part`, resuming from its current size when the server allows it."""
    offset = part.stat().st_size if part.exists() else 0
    if offset >= remote.size:
        part.unlink()
        offset = 0
    with _open_url(remote.url, config.timeout_seconds, offset) as response:
        resumed = offset > 0 and response.status == 206
        with part.open("ab" if resumed else "wb") as handle:
            shutil.copyfileobj(response, handle, config.chunk_bytes)
    if part.stat().st_size != remote.size:
        raise ConnectionError(f"{remote.name}: connection ended before the end of the file")


def download_file(remote: RemoteFile, target: Path, config: DownloadConfig) -> None:
    """Download one file to `target` and verify it, skipping a valid existing copy.

    Raises:
        ChecksumError: If the finished download does not match the published MD5.
    """
    if is_valid_download(target, remote, config.chunk_bytes):
        logger.info("%s: already downloaded, checksum matches", remote.name)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    logger.info("%s: downloading %.2f GB", remote.name, remote.size / 1e9)
    with_retries(
        lambda: _stream_to_part(remote, part, config), config.max_retries, config.backoff_seconds
    )
    actual = md5_file(part, config.chunk_bytes)
    if actual != remote.md5:
        part.unlink()
        raise ChecksumError(f"{remote.name}: md5 {actual}, expected {remote.md5}")
    part.replace(target)
    logger.info("%s: downloaded, checksum matches", remote.name)


def download_source(source: SourceConfig, zips_dir: Path, config: DownloadConfig) -> list[Path]:
    """Download every file of a source into `zips_dir` and return their paths."""
    zips_dir.mkdir(parents=True, exist_ok=True)
    remotes = select_remote_files(fetch_record(source.record, config), source.files)
    missing = [r for r in remotes if not (zips_dir / r.name).is_file()]
    require_free_space(zips_dir, int(sum(r.size for r in missing) * config.min_free_factor))
    paths = []
    for remote in remotes:
        path = zips_dir / remote.name
        download_file(remote, path, config)
        paths.append(path)
    return paths


def select_members(names: Iterable[str], sources: LogSources) -> list[str]:
    """Pick the members of a testbed zip to extract (plan 4.2).

    A member is selected if it matches `extraction.always` or a log family and is not
    excluded, or if it is the log file that belongs to a label file. Other files, such as
    pcaps and system configs, are left in the archive.

    Args:
        names: Member names of the zip, as listed by the archive.
        sources: Log source patterns and extraction rules.

    Returns:
        Selected member names, sorted.
    """
    files = [name for name in names if not name.endswith("/")]
    available = set(files)
    rules = sources.extraction
    selected = {
        name
        for name in files
        if (any(glob_match(name, pattern) for pattern in rules.always) or sources.log_type(name))
        and not any(glob_match(name, pattern) for pattern in rules.exclude)
    }
    for name in files:
        if name.startswith("labels/"):
            log_file = "gather/" + name.removeprefix("labels/")
            if log_file in available:
                selected.add(log_file)
            else:
                logger.warning("%s: no matching log file in the archive", name)
    return sorted(selected)


def extract_members(zip_path: Path, members: Iterable[str], target: Path) -> tuple[int, int]:
    """Extract members into `target`, skipping those already extracted at full size.

    Returns:
        Number of files extracted and number skipped.

    Raises:
        InsufficientDiskError: If the files still to extract do not fit on disk.
    """
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        infos = [archive.getinfo(name) for name in members]
        pending = [
            info
            for info in infos
            if not (target / info.filename).is_file()
            or (target / info.filename).stat().st_size != info.file_size
        ]
        require_free_space(target, sum(info.file_size for info in pending))
        for info in pending:
            archive.extract(info, target)
    return len(pending), len(infos) - len(pending)


def run_download(testbed: str, settings: Settings) -> None:
    """Download a source and extract what the project needs (plan 4.2).

    Args:
        testbed: A key of `download.sources`: a testbed name or `ait_ads`.
        settings: Loaded settings.

    Raises:
        KeyError: If `testbed` is not a configured source.
    """
    if testbed not in settings.download.sources:
        known = sorted(settings.download.sources)
        raise KeyError(f"unknown source {testbed!r}; known sources: {known}")
    source = settings.download.sources[testbed]
    target = settings.paths.raw_dir / testbed
    sources = load_sources(settings.paths.sources_file)
    for path in download_source(source, settings.paths.raw_dir / "zips", settings.download):
        if path.suffix != ".zip":
            target.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target / path.name)
            continue
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
        if source.extract:
            members = [n for n in names if any(glob_match(n, p) for p in source.extract)]
        else:
            members = select_members(names, sources)
        extracted, skipped = extract_members(path, members, target)
        logger.info(
            "%s: %d of %d members selected; %d extracted, %d already present",
            path.name,
            len(members),
            len(names),
            extracted,
            skipped,
        )
