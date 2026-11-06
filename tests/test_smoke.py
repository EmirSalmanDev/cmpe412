"""Smoke tests for the config loader and the CLI stubs."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logtriage.cli import app
from logtriage.config import load_settings

CONFIG = Path(__file__).parents[1] / "configs" / "default.yaml"
STUB_COMMANDS = [
    "index-attack",
    "investigate",
    "evaluate",
    "app",
]
COMMANDS = [
    "download",
    "inventory",
    "prepare",
    "detect",
    "index-attack",
    "investigate",
    "evaluate",
    "app",
]

runner = CliRunner()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's own overrides out of the tests."""
    monkeypatch.delenv("LOGTRIAGE_SEED", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)


def test_default_config_loads() -> None:
    settings = load_settings(CONFIG, env_file=None)
    assert settings.seed == 42
    assert settings.paths.raw_dir == Path("data/raw")
    assert settings.deepseek_api_key is None


def test_env_file_overrides_yaml_and_environment_overrides_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LOGTRIAGE_SEED=7\n", encoding="utf-8")
    assert load_settings(CONFIG, env_file=env_file).seed == 7

    monkeypatch.setenv("LOGTRIAGE_SEED", "8")
    assert load_settings(CONFIG, env_file=env_file).seed == 8


def test_api_key_comes_from_env_and_stays_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("DEEPSEEK_API_KEY: upper\ndeepseek_api_key: lower\n", encoding="utf-8")
    assert load_settings(config, env_file=None).deepseek_api_key is None

    monkeypatch.setenv("DEEPSEEK_API_KEY", "fake-key")
    settings = load_settings(CONFIG, env_file=None)
    assert settings.deepseek_api_key is not None
    assert settings.deepseek_api_key.get_secret_value() == "fake-key"
    assert "fake-key" not in repr(settings)


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in COMMANDS:
        assert command in result.output


@pytest.mark.parametrize("command", STUB_COMMANDS)
def test_stub_commands_accept_options(command: str) -> None:
    result = runner.invoke(app, [command, "--testbed", "santos", "--config", str(CONFIG)])
    assert result.exit_code == 0
    assert "not implemented yet" in result.output


def test_detect_reports_a_testbed_without_features(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"paths:\n  processed_dir: {tmp_path}\n", encoding="utf-8")
    result = runner.invoke(app, ["detect", "--testbed", "nope", "--config", str(config)])
    assert result.exit_code == 1
    assert "detect failed" in result.output


def test_download_rejects_unknown_source() -> None:
    result = runner.invoke(app, ["download", "--testbed", "nope", "--config", str(CONFIG)])
    assert result.exit_code == 1
    assert "unknown source" in result.output


def test_inventory_needs_the_downloaded_testbed() -> None:
    result = runner.invoke(app, ["inventory", "--testbed", "nope", "--config", str(CONFIG)])
    assert result.exit_code == 1
    assert "logtriage download" in result.output


def test_prepare_needs_the_downloaded_testbed() -> None:
    result = runner.invoke(app, ["prepare", "--testbed", "nope", "--config", str(CONFIG)])
    assert result.exit_code == 1
    assert "logtriage download" in result.output
