# LogTriage Agent

LogTriage detects anomalies in AIT-LDS security logs with machine learning. A LangGraph agent then investigates each incident and writes a report that cites its log evidence and maps findings to MITRE ATT&CK.

`download`, `inventory`, `prepare`, `detect`, `index-attack`, `investigate` and `app` work; `evaluate` is still a stub. See `status.md` for progress and `plan.md` for the design.

## Setup

You need [uv](https://docs.astral.sh/uv/). If it is missing, run `pip install uv`. uv manages Python 3.11 and the virtual environment.

On macOS, XGBoost also needs the OpenMP runtime: `brew install libomp`.

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
uv run logtriage detect --testbed russellmitchell
```

`download` fetches into `data/raw/zips/` and extracts only the files the project needs. The archives take about 7 GB for russellmitchell and 10 GB for santos. Rerunning it skips whatever is already in place. `inventory` needs AIT-ADS as well as the testbed; it writes `reports/inventory_<testbed>.md` and `data_meta/phases_<testbed>.csv`. `prepare` parses the logs and writes tables and DuckDB files to `data/processed/<testbed>/`; it takes about 20 seconds per testbed. `detect` fits the anomaly models and writes `scores.parquet` and `incidents.parquet`; it reads no ground truth.

The commands are `download`, `inventory`, `prepare`, `detect`, `index-attack`, `investigate`, `evaluate` and `app`. Each takes `--testbed` and `--config`.

## Dashboard

```
uv run logtriage app --testbed santos
```

Opens the Incidents, Incident detail, Chat and Monitoring pages on http://127.0.0.1:8501. Turn on **Replay mode** in the sidebar to watch incidents close on a simulated clock (60×, 600× or 3600×). The chat needs `DEEPSEEK_API_KEY`, and it spends real money under the limits `llm.max_usd_per_run` and `llm.max_usd_total`. `--live` computes missing reports during a replay; it is refused on santos, which runs the agents once only.

## Docker

You need Docker with Compose 2.24 or later, and `data/processed/` and `data/index/` from the commands above; the image holds no data. On a clean clone with `data/` in place:

```
docker compose up
```

The first run builds the image, about 3.8 GB, which needs network. Then open http://localhost:8501. The dashboard shows santos; to see the dev testbed, set `LOGTRIAGE_TESTBED=russellmitchell` in the environment or in `.env`. Stop it with `docker compose down`.

- **Port:** it is published on the loopback of the host only, because the dashboard shows logs and spends API money. If 8501 is taken, for example by a local `logtriage app`, `up` fails with "address already in use".
- **Key:** `.env` is optional. Without `DEEPSEEK_API_KEY` every page works, and the chat shows its history but does not answer. The key reaches the container as an environment variable; it is never in the image.
- **Network:** a running container needs none, except the chat to reach the LLM. The embedding model is in the image and Hugging Face offline mode is on.
- **Writes:** the chat writes to `data/cache/`, so on Linux that folder must be writable by user id 1000, which the container runs as.
- **Building data** stays a command-line job: `docker compose run --rm app logtriage prepare --testbed russellmitchell`, or run it locally.
- **Santos:** the container never runs the agents on it. `investigate` refuses, even with `--rerun-reason`, and so does `app --live`.

## Settings

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
