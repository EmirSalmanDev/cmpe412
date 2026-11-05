"""The committed notebooks hold small, error-free outputs from one clean run."""

import json
import re
from pathlib import Path

import pytest

NOTEBOOK = Path(__file__).parents[1] / "notebooks" / "01_eda.ipynb"
MAX_TABLE_ROWS = 100
MAX_BYTES = 5_000_000


@pytest.fixture(scope="module")
def code_cells() -> list[dict]:
    cells = json.loads(NOTEBOOK.read_text(encoding="utf-8"))["cells"]
    return [cell for cell in cells if cell["cell_type"] == "code"]


def test_notebook_is_small_enough_to_commit() -> None:
    assert NOTEBOOK.stat().st_size < MAX_BYTES


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


def test_notebook_shows_figures_as_png(code_cells: list[dict]) -> None:
    formats = {key for cell in code_cells for out in cell["outputs"] for key in out.get("data", {})}
    assert "image/png" in formats
