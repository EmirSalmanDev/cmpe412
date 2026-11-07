"""The few-shot examples of the Reporter (D48, D65): valid, invented, and free of any answer.

The checks are functions, so that fixtures can prove each one rejects what it must. The test that
reads real reports and raw lines prints counts only: their text must not reach the session.
"""

import ipaddress
import json
import re
from collections.abc import Iterable, Iterator
from importlib import resources
from pathlib import Path

import pytest
import yaml

from logtriage.agents.prompting import load_prompt, load_prompts
from logtriage.agents.schemas import IncidentReport, ReportDraft, report_claims
from logtriage.data.store import connect

REPO = Path(__file__).resolve().parents[1]
TESTBEDS = ("russellmitchell", "santos", "wardbeck", "harrison")
RFC5737 = [
    ipaddress.ip_network(item) for item in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
ADDRESS = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
DOMAIN = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE)
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
WORD = re.compile(r"[a-z0-9]+")
NAME = re.compile(r"[a-z0-9][a-z0-9_-]*")
OVERLAP = 6
SOURCE = "read_parquet(?, union_by_name = true)"


def example_source() -> str:
    """Return the prompt file as written."""
    package = resources.files("logtriage.agents") / "prompts"
    return (package / "reporter_examples.md").read_text(encoding="utf-8")


def examples() -> list[dict]:
    """Return the json blocks of the prompt file."""
    return [json.loads(item) for item in re.findall(r"```json\n(.*?)```", example_source(), re.S)]


def gold_ids() -> set[str]:
    """Return every technique of the gold mapping."""
    mapping = yaml.safe_load((REPO / "configs/gold_attack_mapping.yaml").read_text("utf-8"))
    return {item for values in mapping["phases"].values() for item in values}


def gold_hits(text: str, gold: set[str]) -> set[str]:
    """Return the gold IDs in a text, a parent or child of a gold ID included."""
    found = set(TECHNIQUE.findall(text))
    parents = {item.split(".")[0] for item in gold}
    return {item for item in found if item in gold or item.split(".")[0] in parents}


def outside_rfc5737(text: str) -> set[str]:
    """Return the addresses of a text that are not documentation addresses."""
    return {
        item
        for item in ADDRESS.findall(text)
        if not any(ipaddress.ip_address(item) in network for network in RFC5737)
    }


def outside_example_tld(text: str) -> set[str]:
    """Return the domains of a text that are not under `.example`, file names left out."""
    names = {item.lower() for item in DOMAIN.findall(text)}
    files = {"log", "md", "json"}
    return {
        item
        for item in names
        if not item.endswith(".example") and item.rsplit(".", 1)[-1] not in files
    }


def word_grams(text: str) -> set[tuple[str, ...]]:
    """Return every run of `OVERLAP` words of a text, in lower case, punctuation ignored."""
    words = WORD.findall(text.lower())
    return {tuple(words[i : i + OVERLAP]) for i in range(len(words) - OVERLAP + 1)}


def shared_grams(grams: set[tuple[str, ...]], texts: Iterable[str]) -> int:
    """Return how many texts share a run of `OVERLAP` words with `grams`."""
    first = {gram[0] for gram in grams}
    hits = 0
    for text in texts:
        words = WORD.findall(text.lower())
        hits += any(
            words[i] in first and tuple(words[i : i + OVERLAP]) in grams
            for i in range(len(words) - OVERLAP + 1)
        )
    return hits


def strings_of(value: object) -> Iterator[str]:
    """Yield every string value of a json document, at any depth."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings_of(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings_of(item)


def test_the_file_holds_two_examples() -> None:
    assert len(examples()) == 2
    assert load_prompt("reporter_examples").version == "reporter-examples-1"


def test_each_example_is_a_valid_report_and_a_valid_draft() -> None:
    for item in examples():
        report = IncidentReport.model_validate(item)
        ReportDraft.model_validate(item)
        known = {line.eid for line in report.evidence}
        assert len(known) == len(report.evidence)
        assert all(set(claim.evidence) <= known for claim in report_claims(report))
        by_eid = {line.eid: line for line in report.evidence}
        assert all(entry.ts == by_eid[entry.claim.evidence[0]].ts for entry in report.timeline)
        assert report.verifier_rounds == 0
        assert report.unsupported_claims_removed == []


def test_few_shot_changes_only_the_reporter_and_its_version() -> None:
    plain, shot = load_prompts(), load_prompts(few_shot=True)
    assert shot["reporter"].version == "reporter-2+reporter-examples-1"
    assert shot["reporter"].text.startswith(plain["reporter"].text)
    assert {role: prompt for role, prompt in plain.items() if role != "reporter"} == {
        role: prompt for role, prompt in shot.items() if role != "reporter"
    }


def test_the_examples_are_invented() -> None:
    source = example_source()
    assert outside_rfc5737(source) == set()
    assert outside_example_tld(source) == set()
    assert gold_hits(source, gold_ids()) == set()
    assert {line["host"] for item in examples() for line in item["evidence"]} == {
        "host-a",
        "host-b",
    }


@pytest.mark.parametrize(
    ("check", "bad", "good"),
    [
        (outside_rfc5737, "client 172.21.0.4", "client 203.0.113.9"),
        (outside_example_tld, "mail.corp.com", "mail.corp.example"),
    ],
)
def test_the_checks_catch_a_real_value(check, bad: str, good: str) -> None:
    assert check(bad)
    assert not check(good)


def test_the_gold_check_catches_ids_and_their_family() -> None:
    gold = {"T1046", "T1048.003"}
    assert gold_hits("maps to T1046", gold) == {"T1046"}
    assert gold_hits("maps to T1048", gold) == {"T1048"}
    assert gold_hits("maps to T1114.003", gold) == set()


def test_the_overlap_check_needs_six_words_in_a_row() -> None:
    grams = word_grams("alpha beta gamma delta epsilon zeta eta")
    assert shared_grams(grams, ["x Alpha, beta: gamma delta epsilon zeta y"]) == 1
    assert shared_grams(grams, ["alpha beta gamma delta epsilon theta zeta"]) == 0


def test_strings_of_reads_every_depth() -> None:
    assert sorted(strings_of({"a": ["x", {"b": "y"}], "c": 1})) == ["x", "y"]


@pytest.mark.data
def test_no_example_text_comes_from_any_testbed() -> None:
    """Assert on counts, so that a failure shows no line of a report or a log."""
    source = example_source()
    grams = word_grams(source)
    tokens = set(NAME.findall(source.lower()))
    addresses = set(ADDRESS.findall(source))
    domains = {item.lower() for item in DOMAIN.findall(source)}
    report_hits = line_hits = name_hits = entity_hits = 0
    con = connect()
    for testbed in TESTBEDS:
        directory = REPO / "data/processed" / testbed
        for path in sorted((directory / "reports").glob(f"{testbed}-*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            report_hits += shared_grams(grams, strings_of(report))
        paths = [str(path) for path in sorted(directory.glob("lines_*.parquet"))]
        assert paths
        lines = con.execute(f"SELECT DISTINCT raw FROM {SOURCE}", [paths])
        while batch := lines.fetchmany(200_000):
            line_hits += shared_grams(grams, (row[0] for row in batch))
        names = con.execute(
            f"SELECT DISTINCT lower(host) FROM {SOURCE.replace('?', '$1')} UNION "
            f'SELECT DISTINCT lower("user") FROM {SOURCE.replace("?", "$1")} '
            'WHERE "user" IS NOT NULL',
            [paths],
        ).fetchall()
        name_hits += sum(row[0] in tokens for row in names)
        for needle in addresses | domains | {"host-a", "host-b"}:
            pattern = f"(^|[^a-z0-9-]){re.escape(needle)}($|[^a-z0-9-])"
            entity_hits += con.execute(
                f"SELECT count(*) FROM {SOURCE} WHERE regexp_matches(lower(raw), ?)",
                [paths, pattern],
            ).fetchone()[0]
    assert report_hits == 0
    assert line_hits == 0
    assert name_hits == 0
    assert entity_hits == 0
