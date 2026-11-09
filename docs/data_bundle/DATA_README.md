# cmpe412 data bundle (LogTriage Agent)

This zip holds the `data/` folder of the LogTriage Agent repository
(https://github.com/EmirSalmanDev/cmpe412) as it stood on 2026-11-09, after M12 (`v2.0`), without the
downloaded archives in `data/raw/zips/`. With it you can, without downloading the datasets and
without an API key:

- run the full test suite, `uv run pytest -m "not live"`, including the tests marked `data`;
- open the dashboard, `uv run logtriage app`, and use Replay mode (the chat needs `DEEPSEEK_API_KEY`
  and spends money);
- regenerate every result table and `reports/results.md` from saved outputs and the cache,
  `uv run logtriage evaluate` (no paid call);
- rerun the dev pipeline on `russellmitchell`: `prepare`, `detect`, the cached agent replay
  (README, "Reproduction").

## Download

- Download location (Google Drive): https://drive.google.com/file/d/15h60rb1mtGtIFSME_K3aMRPNrTzubZtW/view?usp=sharing
- File: `cmpe412-data-bundle-2026-11-09.zip`, 792453451 bytes,
  sha256 `07a43df8b82d7b6bd2d161cec8cabf629d7ee19ed39bf743105f391574260fb2`
  (the same value as the `zip sha256` line in the header of `MANIFEST.txt`).
- Download it in a browser. Drive shows a confirmation page for large files before the download
  starts; command-line downloads are not tested.
- An AI assistant cannot download it. You download the zip yourself and put it in the repository
  root; then the steps in "How to install" and "How to verify" below apply.

## What is inside (about 4.8 GB unpacked; exact list in `MANIFEST.txt`)

| Path | What it is | Why it is included |
|---|---|---|
| `data/processed/<testbed>/` (all six) | parsed lines, windows, scores, incidents, DuckDB files, agent reports, ablations, v2 outputs | dashboard, replay, `evaluate`, data tests |
| `data/index/chroma/` | ATT&CK retrieval index | agent tools, chat, data tests |
| `data/cache/` | LLM cache and ledger (`llm.sqlite`), chat memory, faithfulness keys | replay and `evaluate` with 0 paid calls |
| `data/logs/` | run logs of the once-only runs | record only |
| `data/raw/ait_ads/` | AIT-ADS IDS alerts for the six testbeds and the published phase labels `labels.csv` | IDS baseline in `evaluate`, data tests |
| `data/raw/attack/enterprise-attack.json` | MITRE ATT&CK Enterprise 20.1 STIX bundle | `index-attack`, `evaluate`, data tests |
| `data/raw/russellmitchell/` | raw logs and labels of the dev testbed | dev `inventory` and `prepare`, data tests |
| `data/raw/santos/` | raw logs and labels of the main test testbed | read only by the inventory data test (`tests/test_data_inventory.py`); `prepare` stays refused on it |

Not included: `data/raw/zips/` (the 85 GB of downloaded archives), the raw logs of `wardbeck`,
`harrison`, `shaw` and `fox` (no allowed operation reads them), and two run logs that hold absolute
paths of the maintainer's machine.

Outside `data/` you still need: `uv sync`, and on the first data test or chat question the embedding
model `BAAI/bge-small-en-v1.5` (about 130 MB) is downloaded from Hugging Face into its usual cache.

## Testbeds and the once-only rule

- Dev testbed: `russellmitchell`. Every choice was tuned here, and every command may run on it.
- Test testbeds: `santos` (the frozen targets), `wardbeck` and `harrison` (extra test testbeds),
  `shaw` and `fox` (the unseen testbeds of M12, v2). `test_testbeds` in `configs/default.yaml`.

Each test testbed has already run `prepare`, `detect`, the supervised stage and `investigate` once,
and the results are in this bundle. **Never run `prepare`, `detect`, `investigate` or the supervised
stage on a test testbed, and never use `--rerun-reason`.** Every such run is recorded in
`reports/results/test_runs.csv` (in the repository); a second run would make the published test
results invalid. Read the saved outputs instead: `evaluate`, the dashboard and the notebooks do.

## How to install

1. Clone the repository and run `uv sync` (see the README, "Setup").
2. Put the zip in the repository root and extract it there, so that `data/` sits next to `src/`:
   ```
   cd cmpe412
   unzip cmpe412-data-bundle-2026-11-09.zip
   ```
   (On Windows: "Extract all" into the repository folder.) If a `data/` folder already exists,
   extract into an empty copy of the repository instead of mixing the two.
3. Run `uv run pytest -m "not live"`.

## How to verify

Check the zip itself against the sha256 in `MANIFEST.txt` before extracting:
```
shasum -a 256 cmpe412-data-bundle-2026-11-09.zip      # macOS
sha256sum cmpe412-data-bundle-2026-11-09.zip          # Linux
```

Then, from the repository root, check every extracted file against the list (a copy of the list is in
the zip as `data/BUNDLE_MANIFEST.txt`); the command prints nothing when all files match. The list the
command reads is `data/BUNDLE_MANIFEST.txt` inside the zip, which is the same list as
`docs/data_bundle/MANIFEST.txt` in the repository:
```
grep -v '^#' data/BUNDLE_MANIFEST.txt | awk '{print $1"  "$3}' | shasum -a 256 -c --quiet   # macOS
grep -v '^#' data/BUNDLE_MANIFEST.txt | awk '{print $1"  "$3}' | sha256sum -c --quiet       # Linux
```

## Data license and attribution

This bundle redistributes data derived from public datasets. Keep these notices with every copy.

- **AIT Alert Data Set (AIT-ADS)**, Zenodo record 8263181, <https://doi.org/10.5281/zenodo.8263181>,
  license [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (attribution). Source of
  `data/raw/ait_ads/` (alerts and `labels.csv`).
- **AIT Log Data Set V2.0 (AIT-LDS)**, Zenodo record 5789064, <https://doi.org/10.5281/zenodo.5789064>,
  license [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) (attribution,
  non-commercial use only, share alike). Source of `data/raw/russellmitchell/`, `data/raw/santos/`
  and everything under `data/processed/`, which is derived from the logs. This bundle is shared under
  the same license, for non-commercial use.
- Both by the AIT Austrian Institute of Technology. The records ask users to cite:
  - M. Landauer, F. Skopik, M. Frank, W. Hotwagner, M. Wurzenberger, and A. Rauber. "Maintainable Log
    Datasets for Evaluation of Intrusion Detection Systems." IEEE Transactions on Dependable and
    Secure Computing, vol. 20, no. 4, pp. 3466–3482, 2023. doi: 10.1109/TDSC.2022.3201582.
    (AIT-LDS and AIT-ADS)
  - M. Landauer, F. Skopik, M. Wurzenberger, W. Hotwagner, and A. Rauber. "Have it Your Way:
    Generating Customized Log Datasets With a Model-Driven Simulation Testbed." IEEE Transactions on
    Reliability, vol. 70, no. 1, pp. 402–415, March 2021. doi: 10.1109/TR.2020.3031317. (AIT-LDS)
  - M. Landauer, F. Skopik, and M. Wurzenberger. "Introducing a New Alert Data Set for Multi-Step
    Attack Analysis." Proceedings of the 17th Cyber Security Experimentation and Test Workshop, 2024.
    doi: 10.1145/3675741.3675748. (AIT-ADS)
- **MITRE ATT&CK** Enterprise 20.1 (`data/raw/attack/enterprise-attack.json`, from the
  `attack-stix-data` repository) and the ATT&CK index built from it: © 2026 The MITRE Corporation.
  This work is reproduced and distributed with the permission of The MITRE Corporation. MITRE ATT&CK
  and ATT&CK are registered trademarks of The MITRE Corporation. Terms of use:
  <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>.
