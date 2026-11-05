"""Configuration loader: `configs/default.yaml` into a Pydantic settings object (plan 3).

Precedence, highest first: environment variables, `.env`, YAML file, field defaults.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

DEFAULT_CONFIG_PATH = Path("configs/default.yaml")
DEFAULT_ENV_FILE = Path(".env")
DEV_TESTBED = "russellmitchell"
TEST_TESTBED = "santos"


class PlaceholderSection(BaseModel):
    """Config section whose keys are defined by a later milestone."""

    model_config = ConfigDict(extra="allow")


class LLMConfig(PlaceholderSection):
    """LLM endpoint settings (plan 7.1). The API key is not part of this section."""

    model: str | None = None
    base_url: str | None = None


class MLConfig(PlaceholderSection):
    """Anomaly detection settings (plan 6.4-6.6)."""


class PeriodsConfig(PlaceholderSection):
    """Period settings (plan 4.3)."""


class PathsConfig(BaseModel):
    """Project paths, relative to the repository root (plan 12)."""

    data_dir: Path = Path("data")
    raw_dir: Path = Path("data/raw")
    processed_dir: Path = Path("data/processed")
    index_dir: Path = Path("data/index")
    cache_dir: Path = Path("data/cache")
    data_meta_dir: Path = Path("data_meta")
    reports_dir: Path = Path("reports")
    sources_file: Path = Path("configs/sources.yaml")


class PhasesConfig(BaseModel):
    """Attack phase settings (plan 5.3)."""

    intervals_file: str = "labels.csv"
    tolerance_seconds: float = 60.0
    exfil_log: str = "gather/attacker_0/logs/dnsteal.log"
    exfil_phase: str = "dnsteal_exfil"
    steps: dict[str, list[str]] = Field(default_factory=dict)


class SourceConfig(BaseModel):
    """One downloadable dataset: a Zenodo record and the files wanted from it."""

    record: int
    files: list[str]
    extract: list[str] = Field(default_factory=list)


class DownloadConfig(BaseModel):
    """Dataset download settings (plan 4.2)."""

    api_url: str = "https://zenodo.org/api/records"
    sources: dict[str, SourceConfig] = Field(default_factory=dict)
    max_retries: int = 3
    backoff_seconds: float = 10.0
    timeout_seconds: float = 60.0
    chunk_bytes: int = 8 * 1024 * 1024
    min_free_factor: float = 5.0


class Settings(BaseSettings):
    """Global settings. Use `load_settings` to build one from a YAML file."""

    model_config = SettingsConfigDict(
        env_prefix="LOGTRIAGE_",
        env_nested_delimiter="__",
        env_file=DEFAULT_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    seed: int = 42
    llm: LLMConfig = Field(default_factory=LLMConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    periods: PeriodsConfig = Field(default_factory=PeriodsConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    phases: PhasesConfig = Field(default_factory=PhasesConfig)
    deepseek_api_key: SecretStr | None = Field(default=None, validation_alias="DEEPSEEK_API_KEY")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Rank init values (the YAML contents) below the environment and `.env`."""
        return env_settings, dotenv_settings, init_settings, file_secret_settings


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a path glob: `*` stays within one path segment, `**` crosses segments."""
    parts = (re.escape(part).replace(r"\*", "[^/]*") for part in pattern.split("**"))
    return re.compile(".*".join(parts) + r"\Z")


def glob_match(path: str, pattern: str) -> bool:
    """Return True if a relative POSIX path matches a path glob."""
    return _glob_regex(pattern).match(path) is not None


class ExtractionRules(BaseModel):
    """Zip members to extract besides the log families and labeled logs (plan 4.2)."""

    always: list[str]
    exclude: list[str]


class LogSources(BaseModel):
    """Contents of `configs/sources.yaml`: path patterns to log types and extraction rules."""

    log_types: dict[str, list[str]]
    other_labeled: list[str]
    extraction: ExtractionRules

    def log_type(self, path: str) -> str | None:
        """Return the log type of a path, or None if it is outside the log families."""
        for log_type, patterns in self.log_types.items():
            if any(glob_match(path, pattern) for pattern in patterns):
                return log_type
        return None

    def is_other_labeled(self, path: str) -> bool:
        """Return True if a path is a known labeled source outside the log families."""
        return any(glob_match(path, pattern) for pattern in self.other_labeled)


def load_sources(path: Path | str) -> LogSources:
    """Load `configs/sources.yaml`."""
    with Path(path).open(encoding="utf-8") as handle:
        return LogSources.model_validate(yaml.safe_load(handle))


def load_settings(
    config_path: Path | str = DEFAULT_CONFIG_PATH,
    env_file: Path | str | None = DEFAULT_ENV_FILE,
) -> Settings:
    """Load settings from a YAML file, applying `.env` and environment overrides.

    Args:
        config_path: YAML config file.
        env_file: Dotenv file to read, or None to skip it. A missing file is ignored.

    Returns:
        The validated settings.
    """
    with Path(config_path).open(encoding="utf-8") as handle:
        values: dict[str, Any] = yaml.safe_load(handle) or {}
    # The API key must come from the environment, never from a config file.
    values = {key: value for key, value in values.items() if key.lower() != "deepseek_api_key"}
    return Settings(_env_file=env_file, **values)
