"""Configuration loader: `configs/default.yaml` into a Pydantic settings object (plan 3).

Precedence, highest first: environment variables, `.env`, YAML file, field defaults.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

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
# The test testbed of the frozen targets. All test testbeds are in `Settings.test_testbeds` (D56).
TEST_TESTBED = "santos"
# The test testbeds of the M11 evaluation and of the pooled row of plan 10.7, fixed by D56. Later
# test testbeds (M12: shaw and fox) join `test_testbeds`, so every guard covers
# them, but not this list: the official v1 results and `logtriage evaluate` stay as they are (D83).
M11_TESTBEDS = ("santos", "wardbeck", "harrison")


class PlaceholderSection(BaseModel):
    """Config section whose keys are defined by a later milestone."""

    model_config = ConfigDict(extra="allow")


class TokenPrices(BaseModel):
    """USD per million tokens."""

    input: float = 0.0
    cached_input: float = 0.0
    output: float = 0.0


class PricingConfig(BaseModel):
    """Rates of the two daily bands (plan 7.1, D45)."""

    off_peak: TokenPrices = Field(default_factory=TokenPrices)
    peak: TokenPrices = Field(default_factory=TokenPrices)


class LLMConfig(BaseModel):
    """LLM endpoint and spending settings (plan 7.1). The API key is not part of this section."""

    model: str = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    temperature: float = 0.0
    thinking: Literal["enabled", "disabled"] = "disabled"
    max_tokens: int = 8192
    timeout_seconds: float = 120.0
    http_retries: int = 2
    json_retries: int = 2
    max_usd_per_run: float = 5.0
    max_usd_total: float = 10.0
    pricing_usd_per_1m: PricingConfig = Field(default_factory=PricingConfig)
    peak_hours_utc: list[tuple[int, int]] = Field(default_factory=list)


class AgentsConfig(BaseModel):
    """Limits and ablation switches of the agent graph (plan 7.2, 7.4, 10.4)."""

    max_tool_calls: int = 8
    max_evidence: int = 30
    evidence_chars: int = 500
    max_rewrites: int = 2
    mapper_k: int = 10
    max_techniques: int = 3
    candidate_chars: int = 400
    context_windows: int = 40
    verifier: bool = True
    rag: bool = True
    few_shot: bool = False
    prompts_frozen: bool = False

    @property
    def condition(self) -> dict[str, bool]:
        """Return the ablation switches, as stored in report meta and in the cache key."""
        return {"verifier": self.verifier, "rag": self.rag, "few_shot": self.few_shot}


class AppConfig(BaseModel):
    """Dashboard and replay settings (plan 9.1)."""

    # Local only by default: the dashboard shows logs and spends API money. M10 sets it for Docker.
    host: str = "127.0.0.1"
    port: int = 8501
    speeds: list[int] = Field(default_factory=lambda: [60, 600, 3600])
    default_speed: int = 600
    # Seconds of wall time between two updates of the replay.
    tick_seconds: float = 2.0
    # The replay starts this long before the earliest incident.
    replay_lead_minutes: int = 60
    # Windows shown on each side of an incident in its timeline.
    timeline_context_minutes: int = 60


class SupervisedConfig(BaseModel):
    """Supervised reference settings, fixed and never searched (plan 6.7)."""

    rf_trees: int = 300
    rf_class_weight: str = "balanced_subsample"
    xgb_trees: int = 300
    xgb_max_depth: int = 4
    xgb_learning_rate: float = 0.1
    cv_blocks: int = 5
    purge_minutes: int = 30
    min_positives: int = 5
    training_periods: list[str] = Field(default_factory=lambda: ["calib", "eval"])
    all_periods: list[str] = Field(default_factory=lambda: ["fit", "calib", "eval"])


class MLConfig(PlaceholderSection):
    """Anomaly detection settings (plan 6.3-6.6)."""

    min_fit_lines: int = 200
    min_calib_lines: int = 50
    incidents_per_day_budget: int = 25
    if_estimators: int = 300
    lof_neighbors: int = 35
    lof_max_windows: int = 50_000
    pca_variance: float = 0.95
    min_calib_windows: int = 200
    oof_folds: int = 5
    q: float = 0.99
    gap_minutes: int = 10
    q_grid: list[float] = Field(default_factory=lambda: [0.95, 0.97, 0.98, 0.99, 0.995, 0.999])
    gap_grid: list[int] = Field(default_factory=lambda: [5, 10, 15, 30])
    common_entity_share: float = 0.5
    # v2 switches (reports/v2_plan.md §3). The defaults are v1, so `configs/default.yaml` needs
    # no key for them. `oof_reference` is D28; `cross_fit` is candidate (a) (D75).
    thin_calibration: Literal["oof_reference", "cross_fit"] = "oof_reference"
    # Window features the models use only when listed here, such as `n_unseen_units` (D76).
    optional_features: list[str] = Field(default_factory=list)
    supervised: SupervisedConfig = Field(default_factory=SupervisedConfig)


class ToolsConfig(BaseModel):
    """Limits of the agent tools (plan 7.2, 7.3)."""

    output_chars: int = 4000
    line_chars: int = 300
    sql_rows: int = 200
    sql_timeout_seconds: float = 10.0
    log_search_limit: int = 50
    top_templates: int = 3
    attack_k: int = 5
    incidents_k: int = 3


class RagConfig(BaseModel):
    """ATT&CK index and incident memory settings (plan 8)."""

    embedding_model: str = "BAAI/bge-small-en-v1.5"
    # The Docker image holds this revision only, so an empty value cannot load there (D52).
    embedding_revision: str | None = None
    query_prefix: str = "Represent this sentence for searching relevant passages: "
    attack_sha256: str = ""
    attack_version: str = ""
    attack_collection: str = "attack"
    incidents_collection: str = "incidents"
    bm25_k1: float = 1.5
    bm25_b: float = 0.75
    rrf_k: int = 60


class FeaturesConfig(BaseModel):
    """Window and feature settings (plan 5.4, 6.3)."""

    window_seconds: int = 60
    top_entities: int = 10
    second_level_suffixes: list[str] = Field(
        default_factory=lambda: ["ac", "co", "com", "edu", "go", "gov", "ne", "net", "or", "org"]
    )
    one_sided_features: list[str] = Field(default_factory=list)


class PeriodsConfig(BaseModel):
    """Training and evaluation boundary settings (plan 4.3)."""

    gap_hours: float = 24.0
    min_training_hours: float = 24.0
    fallback_gap_hours: float = 6.0
    fit_fraction: float = 0.8


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
    gold_mapping_file: Path = Path("configs/gold_attack_mapping.yaml")
    attack_stix_file: Path = Path("data/raw/attack/enterprise-attack.json")


class MaskingRule(BaseModel):
    """One Drain3 masking instruction."""

    pattern: str
    mask_with: str


class DrainConfig(BaseModel):
    """Drain3 settings (plan 6.2)."""

    sim_th: float = 0.4
    depth: int = 4
    max_children: int = 100
    masking: list[MaskingRule] = Field(default_factory=list)


class PhasesConfig(BaseModel):
    """Attack phase settings (plan 5.3)."""

    intervals_file: str = "labels.csv"
    tolerance_seconds: float = 60.0
    exfil_log: str = "gather/attacker_0/logs/dnsteal.log"
    exfil_phase: str = "dnsteal_exfil"
    exfil_label: str = "dnsteal"
    steps: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def published_source(self) -> str:
        """`source` value of the phase rows taken from AIT-ADS as published."""
        return f"ait_ads:{self.intervals_file}"


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
    test_testbeds: list[str] = Field(default_factory=lambda: [TEST_TESTBED])
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    rag: RagConfig = Field(default_factory=RagConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    periods: PeriodsConfig = Field(default_factory=PeriodsConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    phases: PhasesConfig = Field(default_factory=PhasesConfig)
    drain: DrainConfig = Field(default_factory=DrainConfig)
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


BASE_KEY = "base"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Return `base` with `override` laid over it; nested mappings merge, other values replace."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def read_config_values(config_path: Path | str, seen: tuple[Path, ...] = ()) -> dict[str, Any]:
    """Read a YAML config, resolving its optional `base` file first.

    A config with `base: default.yaml` holds only what differs from that file, which is read
    relative to the config's own folder. `configs/v2.yaml` uses it, so it cannot drift from v1.

    Args:
        config_path: YAML config file.
        seen: Files already on the chain, to refuse a loop.

    Returns:
        The merged values, without the `base` key.

    Raises:
        ValueError: If the chain of `base` files loops.
    """
    path = Path(config_path).resolve()
    if path in seen:
        raise ValueError(f"{config_path}: the chain of base configs loops")
    with path.open(encoding="utf-8") as handle:
        values: dict[str, Any] = yaml.safe_load(handle) or {}
    base = values.pop(BASE_KEY, None)
    if base is None:
        return values
    return deep_merge(read_config_values(path.parent / base, (*seen, path)), values)


def load_settings(
    config_path: Path | str = DEFAULT_CONFIG_PATH,
    env_file: Path | str | None = DEFAULT_ENV_FILE,
) -> Settings:
    """Load settings from a YAML file, applying `.env` and environment overrides.

    Args:
        config_path: YAML config file, optionally naming a `base` file it extends.
        env_file: Dotenv file to read, or None to skip it. A missing file is ignored.

    Returns:
        The validated settings.
    """
    values = read_config_values(config_path)
    # The API key must come from the environment, never from a config file.
    values = {key: value for key, value in values.items() if key.lower() != "deepseek_api_key"}
    return Settings(_env_file=env_file, **values)
