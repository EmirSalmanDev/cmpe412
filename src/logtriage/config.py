"""Configuration loader: `configs/default.yaml` into a Pydantic settings object (plan 3).

Precedence, highest first: environment variables, `.env`, YAML file, field defaults.
"""

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
