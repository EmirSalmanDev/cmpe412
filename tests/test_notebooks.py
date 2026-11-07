"""The committed notebooks hold small, error-free outputs from one clean run."""

import json
import re
from pathlib import Path

import pytest

NOTEBOOKS = Path(__file__).parents[1] / "notebooks"
NAMES = [
    "01_eda.ipynb",
    "02_preparation.ipynb",
    "03_ml_models.ipynb",
    "04_agents.ipynb",
    "05_evaluation.ipynb",
]
MAX_TABLE_ROWS = 100
MAX_BYTES = 5_000_000


@pytest.fixture(scope="module", params=NAMES)
def notebook(request: pytest.FixtureRequest) -> Path:
    return NOTEBOOKS / request.param


@pytest.fixture(scope="module")
def code_cells(notebook: Path) -> list[dict]:
    cells = json.loads(notebook.read_text(encoding="utf-8"))["cells"]
    return [cell for cell in cells if cell["cell_type"] == "code"]


def test_notebook_is_small_enough_to_commit(notebook: Path) -> None:
    assert notebook.stat().st_size < MAX_BYTES


def test_notebook_ran_in_order_from_a_clean_kernel(code_cells: list[dict]) -> None:
    assert [cell["execution_count"] for cell in code_cells] == list(range(1, len(code_cells) + 1))


def test_notebook_has_no_error_output(code_cells: list[dict]) -> None:
    kinds = {output["output_type"] for cell in code_cells for output in cell["outputs"]}
    assert "error" not in kinds


def test_notebook_tables_stay_under_the_row_limit(code_cells: list[dict]) -> None:
    for cell in code_cells:
        for output in cell["outputs"]:
            html = "".join(output.get("data", {}).get("text/html", []))
            assert len(re.findall(r"<tr", html)) <= MAX_TABLE_ROWS + 2


def test_the_eda_notebook_shows_figures_as_png() -> None:
    cells = json.loads((NOTEBOOKS / NAMES[0]).read_text(encoding="utf-8"))["cells"]
    outputs = [out for cell in cells if cell["cell_type"] == "code" for out in cell["outputs"]]
    assert "image/png" in {key for out in outputs for key in out.get("data", {})}


def test_the_evaluation_notebook_only_reads_saved_results() -> None:
    cells = json.loads((NOTEBOOKS / NAMES[4]).read_text(encoding="utf-8"))["cells"]
    code = "\n".join("".join(cell["source"]) for cell in cells if cell["cell_type"] == "code")
    for word in ("run_detect", "run_incidents", "run_ablation", "run_sample", "LLMClient", ".fit("):
        assert word not in code
    assert "read_parquet" not in code
