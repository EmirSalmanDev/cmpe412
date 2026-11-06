"""Agent tools (plan 7.3), on fixtures, with a fake embedder: no network and no LLM."""

import json
from collections.abc import Iterator
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logtriage.agents.tools import AgentTools, ToolResult, clip, fit_blocks, parse_time
from logtriage.config import RagConfig, ToolsConfig
from logtriage.data.parsers import vpn
from logtriage.data.parsers.common import ParseContext
from logtriage.data.store import build_agent_db, connect_agent, write_lines
from logtriage.rag.attack_index import (
    AttackIndex,
    build_index,
    cosine_collection,
    load_techniques,
    open_client,
)
from logtriage.rag.incident_store import IncidentStore
from rag_fakes import BUNDLE, FakeEmbedder, report

FIXTURE = Path(__file__).parent / "fixtures" / "logs" / "openvpn.log"
TS = datetime(2022, 1, 24, 3, 0, tzinfo=UTC)
START = "2022-01-24T02:59:00"
END = "2022-01-24T03:30:00"
LABELS = "labels.parquet"
PHASES = "phases_x.csv"


def row(number: int, **changes) -> dict:
    values = {
        "line_id": f"web|logs/access.log|{number}",
        "testbed": "x",
        "host": "web",
        "log_type": "apache_access",
        "file": "logs/access.log",
        "line_no": number,
        "ts": TS + timedelta(seconds=number),
        "raw": f"GET /page/{number} 200",
        "message": "GET",
        "template_id": 1,
        "template": "GET <*> 200",
        "is_unseen_template": False,
        "template_rarity": 1.0,
        "src_ip": "192.168.1.5",
        "user": None,
        "fields": "{}",
        "parse_ok": True,
    }
    return values | changes


def vpn_rows() -> list[dict]:
    """Parse the OpenVPN fixture, as `prepare` does."""
    context = ParseContext(sim_start=datetime(2022, 1, 14, tzinfo=UTC))
    rows = []
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    for number, raw in enumerate(lines, 1):
        parsed = vpn.parse_line(raw, context)
        if parsed.ok:
            rows.append(
                row(
                    number,
                    line_id=f"vpn|logs/openvpn.log|{number}",
                    host="vpn",
                    log_type="vpn",
                    file="logs/openvpn.log",
                    ts=parsed.ts,
                    raw=raw,
                    message=parsed.message,
                    template="vpn",
                    template_id=number,
                    src_ip=parsed.src_ip,
                    user=parsed.user,
                    fields=json.dumps(parsed.fields),
                )
            )
    return rows


def web_rows() -> list[dict]:
    common = [row(number) for number in range(1, 6)]
    rare = row(6, template_id=2, template="POST <*>", raw="POST /rare 500", template_rarity=5.0)
    unseen = row(
        7,
        template_id=3,
        template="ODD",
        raw="ODD 100% line",
        is_unseen_template=True,
        template_rarity=9.0,
    )
    broken = row(
        8,
        template_id=None,
        template=None,
        raw="stderr text with an inherited time",
        is_unseen_template=None,
        template_rarity=None,
        parse_ok=False,
    )
    return [*common, rare, unseen, broken]


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    write_lines(web_rows(), tmp_path / "lines_apache_access.parquet")
    write_lines(vpn_rows(), tmp_path / "lines_vpn.parquet")
    (tmp_path / LABELS).write_bytes(b"not read")
    (tmp_path / PHASES).write_text("testbed,phase\nx,dirb\n", encoding="utf-8")
    build_agent_db(tmp_path)
    return tmp_path


@pytest.fixture
def tools(directory: Path) -> Iterator[AgentTools]:
    client = open_client(directory)
    build_index(load_techniques(BUNDLE), client, FakeEmbedder(), "attack")
    attack = AttackIndex(cosine_collection(client, "attack"), FakeEmbedder(), RagConfig())
    incidents = IncidentStore(cosine_collection(client, "incidents"), FakeEmbedder())
    connection = connect_agent(directory / "agent.duckdb")
    instance = AgentTools(connection, ToolsConfig(), "x", attack, incidents)
    yield instance
    instance.close()


def test_clip_keeps_one_row_within_the_limit() -> None:
    assert clip("a\n  b", 10) == "a b"
    assert len(clip("x" * 50, 10)) == 10


def test_fit_blocks_keeps_only_the_line_ids_it_shows() -> None:
    blocks = [("a" * 40, "first"), ("b" * 40, "second"), ("c" * 40, "third")]
    text, ids = fit_blocks("head", blocks, 80)
    assert len(text) <= 80
    assert ids == ["first"]
    assert "more not shown" in text


def test_a_time_without_a_zone_is_utc_and_others_are_converted() -> None:
    assert parse_time("2022-01-24T03:00:00") == TS
    assert parse_time("2022-01-24T06:00:00+03:00") == TS


def test_log_search_shows_one_example_and_a_count_per_template(tools: AgentTools) -> None:
    result = tools.log_search("web", START, END)
    assert "5x" in result.text
    assert "7 lines, 3 templates on web" in result.text
    assert len(result.line_ids) == 3


def test_log_search_puts_unseen_first_then_rarer(tools: AgentTools) -> None:
    result = tools.log_search("web", START, END)
    assert result.line_ids == [
        "web|logs/access.log|7",
        "web|logs/access.log|6",
        "web|logs/access.log|1",
    ]
    assert "UNSEEN" in result.text.splitlines()[1]


def test_log_search_leaves_out_unreliable_lines_and_says_so(tools: AgentTools) -> None:
    result = tools.log_search("web", START, END)
    assert "stderr" not in result.text
    assert "web|logs/access.log|8" not in result.line_ids
    assert "1 lines with an unreliable time left out" in result.text


def test_log_search_filters_by_time_host_and_type(tools: AgentTools) -> None:
    assert tools.log_search("web", "2022-01-25", "2022-01-26").line_ids == []
    assert tools.log_search("nobody", START, END).line_ids == []
    assert tools.log_search("web", START, END, log_type="vpn").line_ids == []


def test_log_search_takes_contains_as_plain_text_in_any_case(tools: AgentTools) -> None:
    assert tools.log_search("web", START, END, contains="post").line_ids == [
        "web|logs/access.log|6"
    ]
    assert tools.log_search("web", START, END, contains="100%").line_ids == [
        "web|logs/access.log|7"
    ]
    assert tools.log_search("web", START, END, contains="%").line_ids == ["web|logs/access.log|7"]


def test_log_search_input_cannot_inject_sql(tools: AgentTools) -> None:
    result = tools.log_search("web' OR '1'='1", START, END, contains="'; DROP TABLE lines; --")
    assert result.line_ids == []
    assert tools.log_search("web", START, END).line_ids


def test_log_search_reports_a_bad_time(tools: AgentTools) -> None:
    assert tools.log_search("web", "yesterday", END).text.startswith("error")


def test_log_search_limit_is_capped_by_the_config(directory: Path) -> None:
    with connect_agent(directory / "agent.duckdb") as connection:
        tools = AgentTools(connection, ToolsConfig(log_search_limit=2), "x")
        result = tools.log_search("web", START, END, limit=500)
    assert len(result.line_ids) == 2
    assert "showing 2 templates" in result.text


def test_run_sql_returns_rows_and_their_line_ids(tools: AgentTools) -> None:
    result = tools.run_sql("SELECT line_id, raw FROM lines_apache_access WHERE template_id = 2")
    assert result.line_ids == ["web|logs/access.log|6"]
    assert "POST /rare 500" in result.text


def test_run_sql_without_a_line_id_column_surfaces_none(tools: AgentTools) -> None:
    result = tools.run_sql("SELECT count(*) AS n FROM lines")
    assert result.line_ids == []
    assert result.text.splitlines()[1] == "n"


def test_run_sql_limits_rows(directory: Path) -> None:
    with connect_agent(directory / "agent.duckdb") as connection:
        tools = AgentTools(connection, ToolsConfig(sql_rows=2), "x")
        result = tools.run_sql("SELECT line_id FROM lines")
    assert len(result.line_ids) == 2


def test_run_sql_explains_a_rejection_and_an_error(tools: AgentTools) -> None:
    assert tools.run_sql("DROP TABLE lines").text.startswith("rejected")
    assert tools.run_sql("SELECT nope FROM lines").text.startswith("error")


def test_run_sql_stops_at_the_time_limit(directory: Path) -> None:
    endless = (
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r"
    )
    with connect_agent(directory / "agent.duckdb") as connection:
        tools = AgentTools(connection, ToolsConfig(sql_timeout_seconds=0.2), "x")
        assert tools.run_sql(endless).text.startswith("error")
        assert "1 rows" in tools.run_sql("SELECT 1").text


@pytest.mark.parametrize("name", [LABELS, PHASES])
@pytest.mark.parametrize("absolute", [True, False])
@pytest.mark.parametrize(
    "template",
    [
        "SELECT * FROM read_parquet('{path}')",
        "SELECT * FROM read_csv('{path}')",
        "SELECT * FROM '{path}'",
        'SELECT * FROM "{path}"',
        "WITH a AS (SELECT * FROM read_csv('{path}')) SELECT * FROM a",
        "SELECT * FROM query('SELECT * FROM ''{path}''')",
    ],
)
def test_ground_truth_files_cannot_be_read_through_the_tool(
    directory: Path,
    tools: AgentTools,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    absolute: bool,
    template: str,
) -> None:
    monkeypatch.chdir(directory)
    path = directory / name if absolute else name
    result = tools.run_sql(template.format(path=path))
    assert result.text.startswith("rejected")
    assert result.line_ids == []


def test_ip_profile_resolves_an_external_ip_to_the_vpn_ip_and_user(tools: AgentTools) -> None:
    result = tools.ip_profile("10.229.3.112")
    assert "external 10.229.3.112, vpn 10.8.0.6, user gmorgan" in result.text
    assert "vpn on vpn:" in result.text


def test_ip_profile_resolves_a_vpn_ip_to_the_external_ip_and_user(tools: AgentTools) -> None:
    result = tools.ip_profile("10.8.0.6")
    assert "external 10.229.3.112, vpn 10.8.0.6, user gmorgan" in result.text
    assert result.line_ids == ["vpn|logs/openvpn.log|3"]


def test_ip_profile_lists_each_log_type_and_host(tools: AgentTools) -> None:
    result = tools.ip_profile("192.168.1.5")
    assert "7 lines, 0 VPN session records" in result.text
    assert "apache_access on web: 7 lines" in result.text
    assert "top: GET <*> 200" in result.text
    assert result.line_ids == ["web|logs/access.log|1"]


def test_ip_profile_leaves_out_unreliable_lines(tools: AgentTools) -> None:
    assert "stderr" not in tools.ip_profile("192.168.1.5").text


def test_ip_profile_of_an_unknown_ip_is_empty(tools: AgentTools) -> None:
    result = tools.ip_profile("1.2.3.4")
    assert result.text == "1.2.3.4: 0 lines, 0 VPN session records"
    assert result.line_ids == []


def test_attack_search_returns_techniques_and_no_lines(tools: AgentTools) -> None:
    result = tools.attack_search("guess passwords brute force", 2)
    assert "T1110 Brute Force [credential-access]" in result.text
    assert result.line_ids == []


def test_attack_search_is_capped_by_the_config(tools: AgentTools) -> None:
    tools.config = ToolsConfig(attack_k=1)
    assert tools.attack_search("dns", 3).text.startswith("1 techniques")


def test_similar_incidents_sees_only_earlier_incidents(tools: AgentTools) -> None:
    tools.incidents.add(report("early", "dns tunnel"), "x", TS)
    tools.incidents.add(report("late", "dns tunnel"), "x", TS + timedelta(hours=2))
    tools.before = TS + timedelta(hours=1)
    result = tools.similar_incidents("dns tunnel")
    assert "early [malicious]" in result.text
    assert "late" not in result.text


def test_similar_incidents_on_an_empty_memory(tools: AgentTools) -> None:
    assert tools.similar_incidents("dns").text == "0 incidents"


def test_rag_tools_say_when_there_is_no_index(directory: Path) -> None:
    with connect_agent(directory / "agent.duckdb") as connection:
        tools = AgentTools(connection, ToolsConfig(), "x")
        assert tools.attack_search("dns").text.startswith("error")
        assert tools.similar_incidents("dns").text.startswith("error")


@pytest.fixture
def wide_tools(tmp_path: Path) -> Iterator[AgentTools]:
    """Tools over many long lines, so every output would overflow without its cap."""
    rows = [
        row(
            number,
            raw="x" * 5000,
            template="y" * 5000,
            template_id=number,
            host="web",
            ts=TS + timedelta(seconds=number),
        )
        for number in range(1, 120)
    ]
    write_lines(rows, tmp_path / "lines_apache_access.parquet")
    build_agent_db(tmp_path)
    client = open_client(tmp_path)
    build_index(load_techniques(BUNDLE), client, FakeEmbedder(), "attack")
    attack = AttackIndex(cosine_collection(client, "attack"), FakeEmbedder(), RagConfig())
    incidents = IncidentStore(cosine_collection(client, "incidents"), FakeEmbedder())
    for number in range(5):
        incidents.add(report(f"i{number}", "dns tunnel " * 800), "x", TS)
    connection = connect_agent(tmp_path / "agent.duckdb")
    config = ToolsConfig(output_chars=1000, attack_k=5, incidents_k=5)
    instance = AgentTools(connection, config, "x", attack, incidents)
    yield instance
    instance.close()


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("log_search", ("web", START, END)),
        ("run_sql", ("SELECT line_id, raw, template FROM lines",)),
        ("run_sql", ("SELECT raw FROM nothing_here_" + "z" * 5000,)),
        ("ip_profile", ("192.168.1.5",)),
        ("attack_search", ("dns tunnel",)),
        ("similar_incidents", ("dns tunnel", 5)),
    ],
)
def test_every_tool_output_respects_the_cap(
    wide_tools: AgentTools, name: str, arguments: tuple
) -> None:
    result = getattr(wide_tools, name)(*arguments)
    assert isinstance(result, ToolResult)
    assert len(result.text) <= 1000


def test_a_capped_output_returns_only_the_line_ids_it_shows(wide_tools: AgentTools) -> None:
    result = wide_tools.log_search("web", START, END)
    assert result.line_ids
    assert all(line_id in result.text for line_id in result.line_ids)
    assert len(result.line_ids) < 50


def test_a_result_is_plain_data_for_the_graph(tools: AgentTools) -> None:
    assert set(asdict(tools.log_search("web", START, END))) == {"text", "line_ids"}
