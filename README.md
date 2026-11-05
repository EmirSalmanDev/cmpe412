# LogTriage Agent

LogTriage detects anomalies in AIT-LDS security logs with machine learning. A LangGraph agent then investigates each incident and writes a report that cites its log evidence and maps findings to MITRE ATT&CK.

`download`, `inventory` and `prepare` work; the other CLI commands are still stubs. See `status.md` for progress and `plan.md` for the design.

## Setup

You need [uv](https://docs.astral.sh/uv/). If it is missing, run `pip install uv`. uv manages Python 3.11 and the virtual environment.

```
uv sync
cp .env.example .env
```

Set `DEEPSEEK_API_KEY` in `.env`. This file is gitignored and is the only place the key belongs.

## How to run

Run commands from the repository root.

```
uv run logtriage --help
uv run logtriage download --testbed ait_ads
uv run logtriage download --testbed russellmitchell
uv run logtriage inventory --testbed russellmitchell
uv run logtriage prepare --testbed russellmitchell
```

`download` fetches into `data/raw/zips/` and extracts only the files the project needs. The archives take about 7 GB for russellmitchell and 10 GB for santos. Rerunning it skips whatever is already in place. `inventory` needs AIT-ADS as well as the testbed; it writes `reports/inventory_<testbed>.md` and `data_meta/phases_<testbed>.csv`. `prepare` parses the logs and writes tables and DuckDB files to `data/processed/<testbed>/`; it takes about 20 seconds per testbed.

The commands are `download`, `inventory`, `prepare`, `detect`, `index-attack`, `investigate`, `evaluate` and `app`. Each takes `--testbed` and `--config`.

Settings live in `configs/default.yaml`. Override them with `LOGTRIAGE_`-prefixed variables in the environment or `.env`, using `__` between nested keys, for example `LOGTRIAGE_SEED=7`. The environment wins over `.env`, and `.env` wins over the YAML file.

## Development

```
uv run pytest -m "not live"
uv run ruff check .
uv run ruff format --check .
```

Tests marked `live` call the real LLM API. Tests marked `data` need the downloaded datasets or models. CI runs `pytest -m "not live and not data"`.

## Data license and citation

The AIT datasets are licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/), which requires attribution and allows non-commercial use only. They are not included in this repository. Any work that uses them must cite the sources:

- AIT Log Data Set V2.0 (AIT-LDS): <https://zenodo.org/records/5789064>
- AIT Alert Data Set (AIT-ADS): <https://zenodo.org/records/8263181>

Use the citation given on each Zenodo record.
