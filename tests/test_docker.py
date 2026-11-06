"""The Docker files (plan 9.2), read as text: no Docker needed, so these run in CI."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from logtriage import guards
from logtriage.config import load_settings

ROOT = Path(__file__).parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
IGNORED = (ROOT / ".dockerignore").read_text(encoding="utf-8").split("\n")


@pytest.fixture
def service() -> dict[str, Any]:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["app"]


def build_arg(name: str) -> str:
    return re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE, re.MULTILINE).group(1)


def test_the_image_bakes_the_embedding_model_of_the_config() -> None:
    rag = load_settings(ROOT / "configs" / "default.yaml").rag
    assert build_arg("EMBEDDING_MODEL") == rag.embedding_model
    assert build_arg("EMBEDDING_REVISION") == rag.embedding_revision


def test_the_image_is_offline_and_listens_outside_the_container() -> None:
    assert "HF_HUB_OFFLINE=1" in DOCKERFILE
    assert "TRANSFORMERS_OFFLINE=1" in DOCKERFILE
    assert "LOGTRIAGE_APP__HOST=0.0.0.0" in DOCKERFILE


def test_the_image_writes_the_marker_that_stops_santos_runs() -> None:
    assert f"touch {guards.CONTAINER_MARKER}" in DOCKERFILE


def test_the_image_copies_no_data_and_no_secret() -> None:
    copied = re.findall(r"^COPY (?!--from)(.+)$", DOCKERFILE, re.MULTILINE)
    sources = {source for line in copied for source in line.split()[:-1]}
    assert sources == {
        "pyproject.toml", "uv.lock", ".python-version", "README.md", "src", "configs", "data_meta",
    }  # fmt: skip
    assert "DEEPSEEK" not in DOCKERFILE


@pytest.mark.parametrize("entry", [".env", "data", ".git"])
def test_the_build_context_leaves_out_secrets_and_data(entry: str) -> None:
    assert entry in IGNORED


def test_the_build_context_keeps_the_data_package() -> None:
    assert not [line for line in IGNORED if line.startswith("**") and line.endswith("data")]
    assert "src" not in IGNORED


def test_compose_mounts_data_and_configs_and_starts_the_dashboard(service: dict[str, Any]) -> None:
    assert service["volumes"] == ["./data:/app/data", "./configs:/app/configs"]
    assert service["command"][:2] == ["logtriage", "app"]
    assert "--live" not in service["command"]


def test_compose_publishes_on_the_loopback_of_the_host_only(service: dict[str, Any]) -> None:
    assert service["ports"] == ["127.0.0.1:8501:8501"]


def test_compose_host_setting_cannot_be_changed_by_env_file(service: dict[str, Any]) -> None:
    assert service["environment"]["LOGTRIAGE_APP__HOST"] == "0.0.0.0"


def test_compose_starts_on_a_clean_clone_without_env_file(service: dict[str, Any]) -> None:
    assert service["env_file"] == [{"path": ".env", "required": False}]
