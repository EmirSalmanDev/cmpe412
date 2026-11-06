"""Replay mode (plan 9.1) with a fake clock: what is visible depends on simulated time alone."""

from datetime import UTC, datetime, timedelta

import pandas as pd
import pytest

from logtriage.app.replay import (
    ReplayClock,
    check_live,
    closed_incidents,
    finished_windows,
    missing_reports,
    needs_rerun,
    replay_bounds,
)

T0 = datetime(2022, 1, 16, 8, 0, tzinfo=UTC)
WINDOW = 60
SPEED = 600


def clock(speed: float = SPEED, hours: float = 48) -> ReplayClock:
    return ReplayClock(T0, T0 + timedelta(hours=hours), speed, T0, wall=1000.0)


def incidents() -> pd.DataFrame:
    """Three incidents; the second one closes less than one tick after the first."""
    rows = [
        ("a", T0 + timedelta(minutes=27), T0 + timedelta(minutes=28)),
        ("b", T0 + timedelta(minutes=28), T0 + timedelta(minutes=29)),
        ("c", T0 + timedelta(hours=27), T0 + timedelta(hours=27, minutes=2)),
    ]
    return pd.DataFrame(rows, columns=["incident_id", "start", "end"])


def windows() -> pd.DataFrame:
    starts = [T0 + timedelta(minutes=minute) for minute in range(0, 180)]
    return pd.DataFrame({"window_start": starts})


def test_the_clock_runs_at_600x():
    running = clock().play(wall=1000.0)
    assert running.now(1000.0) == T0
    assert running.now(1001.0) == T0 + timedelta(minutes=10)
    assert running.now(1060.0) == T0 + timedelta(hours=10)


def test_a_stopped_clock_does_not_move():
    assert clock().now(5000.0) == T0


def test_the_clock_stops_at_the_end():
    running = clock(hours=1).play(wall=1000.0)
    assert running.now(1005.0) == T0 + timedelta(minutes=50)
    assert not running.finished(1005.0)
    assert running.now(1007.0) == T0 + timedelta(hours=1)
    assert running.now(99999.0) == T0 + timedelta(hours=1)
    assert running.finished(1007.0)


def test_pause_and_resume_lose_no_time_and_gain_none():
    running = clock().play(wall=1000.0)
    paused = running.pause(wall=1001.0)
    moment = T0 + timedelta(minutes=10)
    assert paused.now(1001.0) == moment
    assert paused.now(9000.0) == moment
    resumed = paused.play(wall=9000.0)
    assert resumed.now(9000.0) == moment
    assert resumed.now(9001.0) == moment + timedelta(minutes=10)


def test_a_change_of_speed_does_not_jump():
    running = clock(speed=60).play(wall=1000.0)
    faster = running.with_speed(600, wall=1010.0)
    assert faster.now(1010.0) == T0 + timedelta(minutes=10)
    assert faster.now(1011.0) == T0 + timedelta(minutes=20)


def test_seek_stays_inside_the_replay():
    start = clock(hours=1)
    assert start.seek(T0 - timedelta(days=1), 1000.0).now(1000.0) == T0
    assert start.seek(T0 + timedelta(days=1), 1000.0).now(1000.0) == start.end
    middle = T0 + timedelta(minutes=30)
    assert start.seek(middle, 1000.0).now(1000.0) == middle


def test_restart_goes_back_and_stops():
    running = clock().play(wall=1000.0)
    again = running.restart(T0, wall=1100.0)
    assert not again.running
    assert again.now(2000.0) == T0


def test_an_incident_shows_exactly_when_it_ends():
    table = incidents()
    end = table["end"].iloc[0]
    assert closed_incidents(table, end - timedelta(seconds=1)).empty
    assert closed_incidents(table, end)["incident_id"].tolist() == ["a"]


def test_a_window_shows_one_length_after_its_start():
    """The time of a window is its start, but it is not over until a window length later."""
    table = windows()
    first = table["window_start"].iloc[0]
    assert finished_windows(table, first, WINDOW).empty
    assert finished_windows(table, first + timedelta(seconds=59), WINDOW).empty
    assert len(finished_windows(table, first + timedelta(seconds=60), WINDOW)) == 1


def test_at_600x_a_coarse_tick_skips_no_incident():
    """One 2 s tick is 20 simulated minutes, longer than these incidents and their gap."""
    running = clock().play(wall=1000.0)
    table = incidents()
    seen: list[list[str]] = []
    for tick in range(0, 300):
        moment = running.now(1000.0 + 2.0 * tick)
        seen.append(closed_incidents(table, moment)["incident_id"].tolist())
    assert seen[0] == []
    assert seen[1] == []  # 08:20
    assert seen[2] == ["a", "b"]  # 08:40: both closed inside one tick, neither is lost
    assert seen[-1] == ["a", "b", "c"]
    assert all(len(after) >= len(before) for before, after in zip(seen, seen[1:], strict=False))


def test_nothing_after_the_clock_is_visible_at_any_tick_of_a_600x_replay():
    running = clock(hours=3).play(wall=1000.0)
    incident_table = incidents()
    window_table = windows()
    for tick in range(0, 12):
        moment = running.now(1000.0 + 2.0 * tick)
        assert (closed_incidents(incident_table, moment)["end"] <= moment).all()
        shown = finished_windows(window_table, moment, WINDOW)
        assert (shown["window_start"] + timedelta(seconds=WINDOW) <= moment).all()
        hidden = window_table.drop(shown.index)
        assert (hidden["window_start"] + timedelta(seconds=WINDOW) > moment).all()


def test_the_visible_set_does_not_depend_on_the_tick_rate():
    """The same simulated time gives the same data, however the clock got there."""
    table = incidents()
    fast = clock(speed=600).play(wall=0.0).now(162.0)
    slow = clock(speed=60).play(wall=0.0).now(1620.0)
    assert fast == slow
    assert closed_incidents(table, fast).equals(closed_incidents(table, slow))


def test_the_replay_starts_from_detection_output():
    start, end = replay_bounds(
        incidents(), pd.DataFrame({"window_start": [T0, T0 + timedelta(days=3)]}), WINDOW,
        timedelta(minutes=10),
    )  # fmt: skip
    assert start == T0 + timedelta(minutes=17)
    assert end == T0 + timedelta(days=3, seconds=WINDOW)


def test_the_replay_never_starts_before_the_first_window():
    scores = pd.DataFrame({"window_start": [T0 + timedelta(minutes=20), T0 + timedelta(hours=30)]})
    start, _ = replay_bounds(incidents(), scores, WINDOW, timedelta(hours=5))
    assert start == T0 + timedelta(minutes=20)


def test_the_replay_ends_after_the_last_incident_too():
    scores = pd.DataFrame({"window_start": [T0]})
    _, end = replay_bounds(incidents(), scores, WINDOW, timedelta(0))
    assert end == incidents()["end"].max()


def test_a_testbed_without_incidents_replays_all_its_windows():
    empty = incidents().iloc[0:0]
    scores = pd.DataFrame({"window_start": [T0, T0 + timedelta(hours=1)]})
    start, end = replay_bounds(empty, scores, WINDOW, timedelta(hours=1))
    assert start == T0
    assert end == T0 + timedelta(hours=1, seconds=WINDOW)


def test_live_is_refused_on_the_test_testbed_only():
    check_live("russellmitchell")
    with pytest.raises(ValueError, match="santos"):
        check_live("santos")


def test_live_takes_closed_incidents_without_a_report_in_closing_order():
    table = incidents()
    assert missing_reports(table, {"b": object()}, set()) == ["a", "c"]


def test_live_never_repeats_an_attempt():
    """A failed incident has no report; asking again on each tick would pay on each tick."""
    assert missing_reports(incidents(), {}, {"a", "b", "c"}) == []


@pytest.mark.parametrize(
    ("follows_clock", "shown", "closed", "expected"),
    [(True, 1, 1, True), (False, 1, 1, False), (False, 1, 2, True), (True, 1, 2, True)],
)
def test_a_tick_redraws_only_what_changed(
    follows_clock: bool, shown: int, closed: int, expected: bool
):
    assert needs_rerun(follows_clock, shown, closed) is expected
