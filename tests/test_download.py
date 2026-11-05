"""Tests for Zenodo metadata parsing, checksums, retries and selective extraction."""

import io
import json
import ssl
import urllib.error
import zipfile
from collections import namedtuple
from pathlib import Path

import pytest

from logtriage.config import DownloadConfig, load_sources
from logtriage.data import download
from logtriage.data.download import (
    ChecksumError,
    InsufficientDiskError,
    RemoteFile,
    download_file,
    extract_members,
    is_valid_download,
    md5_file,
    parse_record,
    require_free_space,
    select_members,
    select_remote_files,
    with_retries,
)

FIXTURES = Path(__file__).parent / "fixtures"
SOURCES = load_sources(Path(__file__).parents[1] / "configs" / "sources.yaml")
HELLO_MD5 = "5d41402abc4b2a76b9719d911017c592"
CONFIG = DownloadConfig(max_retries=1, backoff_seconds=0)


class FakeResponse(io.BytesIO):
    """In-memory HTTP response."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        super().__init__(body)
        self.status = status


def remote(size: int = 5, md5: str = HELLO_MD5) -> RemoteFile:
    return RemoteFile(name="tiny.zip", size=size, md5=md5, url="https://zenodo.example/tiny")


def test_parse_record() -> None:
    record = json.loads((FIXTURES / "zenodo_record.json").read_text(encoding="utf-8"))
    files = parse_record(record)
    assert set(files) == {"tiny.zip", "other.zip"}
    assert files["tiny.zip"] == RemoteFile(
        name="tiny.zip",
        size=5,
        md5=HELLO_MD5,
        url="https://zenodo.example/api/records/1/files/tiny.zip/content",
    )


def test_parse_record_rejects_other_checksums() -> None:
    entry = {"key": "a.zip", "size": 1, "checksum": "sha256:ab", "links": {"self": "u"}}
    with pytest.raises(ValueError, match="md5"):
        parse_record({"files": [entry]})


def test_select_remote_files_reports_missing_file() -> None:
    assert select_remote_files({"tiny.zip": remote()}, ["tiny.zip"]) == [remote()]
    with pytest.raises(KeyError, match="missing.zip"):
        select_remote_files({"tiny.zip": remote()}, ["missing.zip"])


def test_md5_file_reads_in_chunks(tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"hello")
    assert md5_file(path, chunk_bytes=2) == HELLO_MD5


def test_is_valid_download(tmp_path: Path) -> None:
    path = tmp_path / "tiny.zip"
    assert not is_valid_download(path, remote())
    path.write_bytes(b"hello")
    assert is_valid_download(path, remote())
    path.write_bytes(b"jello")
    assert not is_valid_download(path, remote())
    path.write_bytes(b"hello!")
    assert not is_valid_download(path, remote())


def test_require_free_space(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(download.shutil, "disk_usage", lambda _: usage(100, 90, 10))
    require_free_space(tmp_path, 10)
    with pytest.raises(InsufficientDiskError):
        require_free_space(tmp_path, 11)


def test_with_retries_backs_off_then_succeeds() -> None:
    delays: list[float] = []
    calls = iter([ConnectionError("a"), TimeoutError("b"), "done"])

    def action() -> str:
        result = next(calls)
        if isinstance(result, Exception):
            raise result
        return result

    assert with_retries(action, 3, 10, sleep=delays.append) == "done"
    assert delays == [10, 20]


def test_with_retries_gives_up_after_max_retries() -> None:
    delays: list[float] = []

    def action() -> None:
        raise ConnectionError("down")

    with pytest.raises(ConnectionError):
        with_retries(action, 3, 1, sleep=delays.append)
    assert delays == [1, 2, 4]


def test_with_retries_does_not_retry_certificate_errors() -> None:
    delays: list[float] = []

    def action() -> None:
        raise urllib.error.URLError(ssl.SSLCertVerificationError("bad certificate"))

    with pytest.raises(urllib.error.URLError):
        with_retries(action, 3, 1, sleep=delays.append)
    assert delays == []


def test_download_file_skips_valid_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "tiny.zip"
    target.write_bytes(b"hello")

    def fail(*_: object) -> None:
        raise AssertionError("must not touch the network")

    monkeypatch.setattr(download, "_open_url", fail)
    download_file(remote(), target, CONFIG)


def test_download_file_resumes_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tiny.zip"
    (tmp_path / "tiny.zip.part").write_bytes(b"he")
    offsets: list[int] = []

    def open_url(_url: str, _timeout: float, offset: int = 0) -> FakeResponse:
        offsets.append(offset)
        return FakeResponse(b"llo", status=206)

    monkeypatch.setattr(download, "_open_url", open_url)
    download_file(remote(), target, CONFIG)
    assert offsets == [2]
    assert target.read_bytes() == b"hello"
    assert not (tmp_path / "tiny.zip.part").exists()


def test_download_file_restarts_if_server_ignores_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tiny.zip"
    (tmp_path / "tiny.zip.part").write_bytes(b"xx")
    monkeypatch.setattr(download, "_open_url", lambda *_: FakeResponse(b"hello", status=200))
    download_file(remote(), target, CONFIG)
    assert target.read_bytes() == b"hello"


def test_download_file_rejects_bad_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tiny.zip"
    monkeypatch.setattr(download, "_open_url", lambda *_: FakeResponse(b"jello"))
    with pytest.raises(ChecksumError):
        download_file(remote(), target, CONFIG)
    assert not target.exists()
    assert not (tmp_path / "tiny.zip.part").exists()


def test_select_members_follows_the_extraction_rules() -> None:
    names = (FIXTURES / "zip_members.txt").read_text(encoding="utf-8").split("\n")
    assert select_members([name for name in names if name], SOURCES) == [
        "dataset.yaml",
        "gather/attacker_0/logs/attacks.log",
        "gather/attacker_0/logs/dnsteal.log",
        "gather/inet-firewall/logs/dnsmasq.log",
        "gather/intranet_server/logs/apache2/error.log.1",
        "gather/intranet_server/logs/apache2/intranet.smith.test.com-access.log.2",
        "gather/intranet_server/logs/apache2/other_vhosts_access.log",
        "gather/intranet_server/logs/audit/audit.log",
        "gather/intranet_server/logs/auth.log",
        "gather/intranet_server/logs/auth.log.1",
        "gather/monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log",
        "gather/vpn/logs/openvpn.log",
        "labels/intranet_server/logs/apache2/intranet.smith.test.com-access.log.2",
        "labels/monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log",
        "labels/vpn/logs/openvpn.log",
    ]


def test_select_members_keeps_a_labeled_file_even_if_excluded() -> None:
    names = ["labels/a/logs/capture.pcap", "gather/a/logs/capture.pcap", "gather/b/logs/b.pcap"]
    assert select_members(names, SOURCES) == [
        "gather/a/logs/capture.pcap",
        "labels/a/logs/capture.pcap",
    ]


def test_select_members_tolerates_label_without_log() -> None:
    assert select_members(["labels/a/logs/x.log"], SOURCES) == ["labels/a/logs/x.log"]


def test_extract_members_is_selective_and_idempotent(tmp_path: Path) -> None:
    archive = tmp_path / "tiny.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("keep/a.log", "aaa")
        handle.writestr("keep/b.log", "bbbb")
        handle.writestr("skip/c.pcap", "ccc")
    target = tmp_path / "out"

    assert extract_members(archive, ["keep/a.log", "keep/b.log"], target) == (2, 0)
    assert (target / "keep/a.log").read_text() == "aaa"
    assert not (target / "skip").exists()

    assert extract_members(archive, ["keep/a.log", "keep/b.log"], target) == (0, 2)

    (target / "keep/b.log").write_text("b")  # a partial file from an interrupted run
    assert extract_members(archive, ["keep/a.log", "keep/b.log"], target) == (1, 1)
    assert (target / "keep/b.log").read_text() == "bbbb"
