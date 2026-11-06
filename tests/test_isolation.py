"""Label isolation (plan 5.2): only the allowed modules may refer to ground truth."""

import json
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).parents[1] / "src" / "logtriage"
SCANNED = ("data", "ml", "agents", "rag", "app")
ALLOWED = {
    "data/labels.py",
    "data/periods.py",
    "data/inventory.py",
    "data/download.py",
    "ml/supervised.py",
}
FORBIDDEN = re.compile(
    r"labels|phases|eval\.duckdb|label_report|first_attack"
    r"|logtriage\.(?:eval|prepare|ml\.supervised)\b"
    r"|from\s+logtriage\.ml\s+import\s+.*\bsupervised\b"
    r"|from\s+\.+\s*(?:ml\s+)?import\s+.*\bsupervised\b"
    r"|from\s+\.+(?:ml\.)?supervised\b"
    r"|supervised_(?:santos|dev_oof|importance)"
    r"|from\s+logtriage\s+import\s+.*\b(?:eval|prepare)\b"
    r"|from\s+\.+(?:eval|prepare)\b"
    r"|from\s+\.+\s+import\s+.*\b(?:eval|prepare)\b",
    re.IGNORECASE,
)


def violations(package: Path) -> list[str]:
    """Return `path:line` of every forbidden reference outside the allowed modules."""
    found = []
    for directory in SCANNED:
        for path in sorted((package / directory).rglob("*")):
            relative = path.relative_to(package).as_posix()
            if not path.is_file() or path.suffix not in (".py", ".md") or relative in ALLOWED:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if FORBIDDEN.search(line):
                    found.append(f"{relative}:{number}: {line.strip()}")
    return found


def test_no_module_outside_the_allow_list_refers_to_ground_truth() -> None:
    assert violations(PACKAGE) == []


@pytest.mark.parametrize(
    "line",
    [
        "from logtriage.data.labels import build_labels",
        "df = read_parquet('labels.parquet')",
        "path = 'data_meta/phases_santos.csv'",
        "duckdb.connect('eval.duckdb')",
        "from logtriage.eval.metrics import window_recall",
        "import logtriage.eval",
        "from logtriage import eval as evaluation",
        "from ..eval import metrics",
        "from .. import eval",
        "from logtriage.prepare import run_prepare",
        "from logtriage import config, prepare",
        "from ..prepare import run_prepare",
        "path = out_dir / 'label_report.json'",
        "cutoff = periods.first_attack",
        "from logtriage.ml.supervised import run_test",
        "from logtriage.ml import models, supervised",
        "from . import supervised",
        "from .supervised import run_dev",
        "path = 'reports/results/supervised_santos.csv'",
    ],
)
def test_the_scan_catches_a_planted_reference(tmp_path: Path, line: str) -> None:
    module = tmp_path / "ml" / "models.py"
    module.parent.mkdir()
    module.write_text(f"{line}\n", encoding="utf-8")
    assert len(violations(tmp_path)) == 1


@pytest.mark.parametrize(
    "line",
    [
        "from logtriage.data.periods import load_periods",
        "from logtriage.config import Settings",
        "max_label_len = 63",
        "evaluate = model.score(prepared)",
        "# scores of the unsupervised models",
    ],
)
def test_the_scan_accepts_a_harmless_line(tmp_path: Path, line: str) -> None:
    module = tmp_path / "ml" / "models.py"
    module.parent.mkdir()
    module.write_text(f"{line}\n", encoding="utf-8")
    assert violations(tmp_path) == []


def test_the_preparation_notebook_refers_to_no_ground_truth() -> None:
    path = PACKAGE.parents[1] / "notebooks" / "02_preparation.ipynb"
    cells = json.loads(path.read_text(encoding="utf-8"))["cells"]
    source = ["".join(cell["source"]) for cell in cells if cell["cell_type"] == "code"]
    assert [line for text in source for line in text.splitlines() if FORBIDDEN.search(line)] == []


def test_the_allowed_modules_exist() -> None:
    assert [name for name in ALLOWED if not (PACKAGE / name).is_file()] == []
