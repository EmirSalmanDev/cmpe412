"""Auto and AI-annotated faithfulness (plan 10.2, D67), with a fake LLM."""

import json
from pathlib import Path

import pandas as pd
import pytest
from sklearn.metrics import cohen_kappa_score

from agent_fakes import FakeChat, draft, open_tools, settings_for, verdicts
from logtriage.agents.cache import LlmCache
from logtriage.agents.prompting import load_prompts
from logtriage.agents.runner import run_incidents
from logtriage.agents.schemas import IncidentReport
from logtriage.eval import faithfulness as f

DEV = "dev"


def run_with_rewrite(tmp_path: Path) -> tuple:
    """Run one incident whose first draft the Verifier sends back."""
    tools = open_tools(tmp_path, incidents=1)
    settings = settings_for(tmp_path)
    fixed = draft(text="a page was requested")
    chat = FakeChat(
        {
            "reporter": [draft(text="a BAD login page was requested"), fixed],
            "verifier": [lambda messages: verdicts(messages, bad=("BAD",)), verdicts],
        }
    )
    run_incidents(DEV, settings, backend=chat, tools=tools)
    tools.close()
    path = tmp_path / "processed" / DEV / "reports" / "x-0001.json"
    report = IncidentReport.model_validate_json(path.read_text(encoding="utf-8"))
    return settings, report


def traced(tmp_path: Path) -> tuple:
    settings, report = run_with_rewrite(tmp_path)
    cache = LlmCache(tmp_path / "cache" / "llm.sqlite")
    drafts = f.reporter_answers(cache)
    rounds = f.trace_report(report, drafts, load_prompts()["verifier"], cache, settings)
    cache.close()
    return report, rounds


def test_a_report_is_traced_through_its_rounds_by_key(tmp_path: Path) -> None:
    report, rounds = traced(tmp_path)
    assert len(rounds) == 2
    assert "unsupported" in rounds[0].judged.values()
    assert set(rounds[1].judged.values()) == {"supported"}
    assert rounds[0].position < rounds[1].position
    f.check_trace(report, rounds)


def test_a_missing_round_is_refused(tmp_path: Path) -> None:
    report, rounds = traced(tmp_path)
    with pytest.raises(ValueError, match="rounds"):
        f.check_trace(report, rounds[:1])


def test_a_trace_that_ends_elsewhere_is_refused(tmp_path: Path) -> None:
    report, rounds = traced(tmp_path)
    report.summary[0].text = "a claim no draft holds"
    with pytest.raises(ValueError, match="does not hold"):
        f.check_trace(report, rounds)


def test_another_reports_evidence_finds_no_judgment(tmp_path: Path) -> None:
    report, rounds = traced(tmp_path)
    settings = settings_for(tmp_path)
    cache = LlmCache(tmp_path / "cache" / "llm.sqlite")
    other = report.evidence[:1] + [report.evidence[1].model_copy(update={"raw": "another line"})]
    condition = {"verifier": True, "rag": True, "few_shot": False}
    prompt = load_prompts()["verifier"]
    assert f.judgment_of(rounds[0].draft, other, prompt, cache, settings, condition) is None
    cache.close()


def test_the_auto_row_shares() -> None:
    def rounds(*judged: dict) -> list[f.Round]:
        return [f.Round(i, None, item) for i, item in enumerate(judged)]

    row = f._auto_row(
        "t",
        "test",
        [
            rounds({"a": "unsupported", "b": "supported"}, {"a": "supported", "b": "supported"}),
            rounds({"c": "supported"}),
        ],
    )
    assert row["label"] == "self-assessment"
    assert row["first_draft_share"] == pytest.approx(2 / 3)
    assert row["last_round_share"] == 1
    assert row["reports_rewritten"] == 1


@pytest.mark.parametrize(
    "text",
    ["intranet.smith.santos.com", "SANTOS", "mail.wardbeck.info", "x.harrison.com", "hurstwong"],
)
def test_the_mask_hides_testbeds(text: str) -> None:
    masked = f.mask(text).lower()
    for name in ("santos", "wardbeck", "harrison", "hurstwong", "smith"):
        assert name not in masked


def test_a_claim_row_shows_its_lines_and_marks_an_unknown_citation(tmp_path: Path) -> None:
    _, report = run_with_rewrite(tmp_path)
    report.summary[0].evidence = ["E1", "E99"]
    rows = f.claim_rows("santos", "x-0001", f.ON, report, {"E1": "line at santos"})
    lines = json.loads(rows[0]["lines"])
    assert lines == ["line at <org>", "(no such line)"]


def claims_table() -> pd.DataFrame:
    rows = [
        ("santos", "s-1", f.ON, "same claim", '["line"]'),
        ("santos", "s-1", f.OFF, "same claim", '["line"]'),
        ("wardbeck", "w-1", f.ON, "kept", '["k"]'),
        ("wardbeck", "w-1", f.ON, "rewritten", '["r"]'),
        ("wardbeck", "w-1", f.DRAFT_ONLY, "dropped", '["d"]'),
        ("harrison", "h-1", f.ON, "other", '["o"]'),
    ]
    frame = pd.DataFrame(rows, columns=["testbed", "incident_id", "arm", "text", "lines"])
    return frame.assign(claim_key="summary:0", claim_type="summary")


def test_the_sheet_is_blind_and_each_distinct_claim_appears_once() -> None:
    sheet, key = f.build_sheet(claims_table(), 42)
    assert list(sheet.columns) == ["id", "claim", "cited_lines"]
    assert len(sheet) == 5
    assert sheet["id"].is_unique
    assert len(key) == 6
    assert "text" not in key.columns
    shared = key.loc[key["arm"].isin([f.ON, f.OFF]) & (key["testbed"] == "santos"), "id"]
    assert shared.nunique() == 1
    again, _ = f.build_sheet(claims_table(), 42)
    pd.testing.assert_frame_equal(sheet, again)


def test_a_first_draft_claim_must_be_on_the_sheet() -> None:
    sheet, _ = f.build_sheet(claims_table(), 42)
    paired = pd.DataFrame(
        {"incident_id": ["w-1"], "testbed": ["wardbeck"], "text": ["gone"], "lines": ['["x"]']}
    )
    with pytest.raises(ValueError, match="not on the sheet"):
        f.attach_ids(paired, sheet)


def test_parts_hold_the_claims_and_their_lines_only(tmp_path: Path) -> None:
    sheet, _ = f.build_sheet(claims_table(), 42)
    paths = f.rater_parts(sheet, tmp_path, size=2)
    assert len(paths) == 3
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for name in ("santos", "wardbeck", f.ON, f.OFF):
        assert name not in text
    assert text.count("### c") == 5
    assert "LINE: k" in text


def write_labels(directory: Path, ids: list[str], rater: str, supported: set[str]) -> None:
    table = pd.DataFrame(
        {
            "id": ids,
            "label": [f.SUPPORTED if item in supported else f.NOT_SUPPORTED for item in ids],
            "reason_code": "shown",
            "reason": "",
        }
    )
    table.to_csv(directory / f.LABEL_PATTERN.format(rater), index=False)


def test_label_files_must_cover_the_sheet(tmp_path: Path) -> None:
    write_labels(tmp_path, ["c1", "c2"], "a", {"c1"})
    write_labels(tmp_path, ["c1"], "b", {"c1"})
    with pytest.raises(ValueError, match="rater b"):
        f.read_labels(tmp_path, {"c1", "c2"})


def test_an_unknown_label_is_refused(tmp_path: Path) -> None:
    write_labels(tmp_path, ["c1"], "a", {"c1"})
    (tmp_path / "labels_b.csv").write_text(
        "id,label,reason_code,reason\nc1,maybe,other,x\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="unknown labels"):
        f.read_labels(tmp_path, {"c1"})


def labeled(tmp_path: Path) -> tuple:
    claims = claims_table()
    sheet, key = f.build_sheet(claims, 42)
    by_text = dict(zip(sheet["claim"], sheet["id"], strict=True))
    ids = list(sheet["id"])
    write_labels(tmp_path, ids, "a", {by_text[t] for t in ("same claim", "kept", "other")})
    write_labels(
        tmp_path, ids, "b", {by_text[t] for t in ("same claim", "kept", "rewritten", "other")}
    )
    labels = f.read_labels(tmp_path, set(ids))
    paired = key[(key["incident_id"] == "w-1") & key["claim_type"].eq("summary")]
    paired = paired[paired["id"].isin({by_text["kept"], by_text["dropped"]})]
    return key, paired, labels


def test_the_readings_count_a_claim_only_if_both_raters_support_it(tmp_path: Path) -> None:
    key, paired, labels = labeled(tmp_path)
    table = f.readings_table(key, paired, labels, ["santos", "wardbeck", "harrison"])
    rows = table.set_index(["reading", "testbed"])
    pooled = rows.loc[("verifier_on", "pooled")]
    assert pooled["claims"] == 4
    assert pooled["supported_both"] == 3
    assert pooled["share_a"] == 0.75
    assert pooled["share_b"] == 1
    assert rows.loc[("verifier_off", "santos"), "claims"] == 1
    assert rows.loc[("paired_first_draft", "wardbeck"), "supported_both"] == 1
    assert rows.loc[("paired_first_draft", "wardbeck"), "claims"] == 2
    assert rows.loc[("paired_final", "wardbeck"), "claims"] == 2
    assert rows.loc[("paired_draft_only", "wardbeck"), "supported_both"] == 0
    assert rows.loc[("paired_final_only", "wardbeck"), "claims"] == 1


def test_kappa_matches_the_library(tmp_path: Path) -> None:
    key, _, labels = labeled(tmp_path)
    table = f.agreement_table(key, labels, ["santos", "wardbeck", "harrison"]).set_index("scope")
    expected = cohen_kappa_score(labels["label_a"], labels["label_b"])
    assert table.loc["all", "kappa"] == pytest.approx(expected)
    assert table.loc["all", "rows"] == 5
    assert table.loc["all", "agree"] == 4
    assert table.loc["santos", "rows"] == 1
