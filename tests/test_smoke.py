"""Smoke tests for the config loader and the CLI stubs."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logtriage.agents.llm import DeepSeekChat
from logtriage.agents.runner import RunSummary
from logtriage.cli import app
from logtriage.config import load_settings

CONFIG = Path(__file__).parents[1] / "configs" / "default.yaml"
STUB_COMMANDS = [
    "evaluate",
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


def test_investigate_passes_its_options_to_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def fake_run(testbed: str, settings: object, **options: object) -> RunSummary:
        seen.update(options, testbed=testbed)
        return RunSummary(testbed, "run", finished=["a"], spent_usd=0.5, total_spent_usd=1.5)

    monkeypatch.setattr("logtriage.cli.run_incidents", fake_run)
    arguments = ["investigate", "--testbed", "t", "--config", str(CONFIG), "--incident", "a"]
    result = runner.invoke(app, [*arguments, "--no-cache", "--rerun-reason", "why"])
    assert result.exit_code == 0
    assert "1 reports, 0 failed, 0.5000 USD this run, 1.5000 USD in total" in result.output
    assert seen == {
        "testbed": "t",
        "incident_ids": ["a"],
        "use_cache": False,
        "rerun_reason": "why",
    }


def test_investigate_exits_with_an_error_when_the_budget_stops_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    summary = RunSummary("t", "run", aborted="run spend reached the limit")
    monkeypatch.setattr("logtriage.cli.run_incidents", lambda *a, **k: summary)
    result = runner.invoke(app, ["investigate", "--config", str(CONFIG)])
    assert result.exit_code == 2
    assert "stopped: run spend reached the limit" in result.output


def test_investigate_reports_a_refused_run(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise ValueError("santos: reports exist")

    monkeypatch.setattr("logtriage.cli.run_incidents", refuse)
    result = runner.invoke(app, ["investigate", "--config", str(CONFIG)])
    assert result.exit_code == 1
    assert "investigate failed: santos: reports exist" in result.output


def test_a_test_without_the_live_mark_cannot_reach_the_real_llm() -> None:
    """The guard of `conftest.py` must fire before any request leaves."""
    model = DeepSeekChat(model="m", api_key="k", base_url="http://localhost")
    with pytest.raises(pytest.fail.Exception, match="reached the real LLM"):
        model.invoke("hello")


def test_index_attack_reports_a_missing_bundle(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    missing = tmp_path / "missing.json"
    config.write_text(f"paths:\n  attack_stix_file: {missing}\n", encoding="utf-8")
    result = runner.invoke(app, ["index-attack", "--config", str(config)])
    assert result.exit_code == 1
    assert "index-attack failed" in result.output


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
