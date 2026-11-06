"""Replay mode (plan 9.1): a simulated clock, and what it lets the dashboard show.

Everything here is pure. The clock reads wall time only as an argument, and the visible data is a
function of the simulated time alone, so a coarse refresh at 600x can skip no incident.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

import pandas as pd

from logtriage.config import Settings


def check_live(testbed: str, settings: Settings) -> None:
    """Refuse `--live` on a test testbed.

    Live replay runs the agent graph, and a test testbed runs once only (D47), so its dashboard
    uses the saved reports alone.

    Raises:
        ValueError: On a test testbed.
    """
    if testbed in settings.test_testbeds:
        raise ValueError(
            f"{testbed}: --live would run the agent graph again; it uses saved reports"
        )


@dataclass(frozen=True)
class ReplayClock:
    """A simulated clock, immutable: every control returns a new one.

    `position` is the simulated time at the wall reading `wall`, and it moves `speed` simulated
    seconds per wall second while `running`.
    """

    start: datetime
    end: datetime
    speed: float
    position: datetime
    wall: float
    running: bool = False

    def now(self, wall: float) -> datetime:
        """Return the simulated time at a wall reading, never past `end`."""
        if not self.running:
            return self.position
        moved = self.position + timedelta(seconds=(wall - self.wall) * self.speed)
        return min(moved, self.end)

    def finished(self, wall: float) -> bool:
        """Return True once the clock has reached `end`."""
        return self.now(wall) >= self.end

    def play(self, wall: float) -> "ReplayClock":
        """Start or resume from the current time."""
        return replace(self, position=self.now(wall), wall=wall, running=True)

    def pause(self, wall: float) -> "ReplayClock":
        """Stop at the current time."""
        return replace(self, position=self.now(wall), wall=wall, running=False)

    def with_speed(self, speed: float, wall: float) -> "ReplayClock":
        """Change the speed. The simulated time does not jump."""
        return replace(self, position=self.now(wall), wall=wall, speed=speed)

    def seek(self, moment: datetime, wall: float) -> "ReplayClock":
        """Move to a simulated time inside the replay."""
        return replace(self, position=min(max(moment, self.start), self.end), wall=wall)

    def restart(self, start: datetime, wall: float) -> "ReplayClock":
        """Go back to a new start and stop."""
        begin = min(max(start, self.start), self.end)
        return replace(self, position=begin, wall=wall, running=False)


def replay_bounds(
    incidents: pd.DataFrame, scores: pd.DataFrame, window_seconds: int, lead: timedelta
) -> tuple[datetime, datetime]:
    """Return the default start and the end of a replay, from detection output alone.

    Args:
        incidents: Incidents, with `start` and `end`.
        scores: Scored windows, with `window_start`.
        window_seconds: Window length.
        lead: How long before the earliest incident to start.

    Returns:
        Start and end. Without incidents the replay starts at the first window.
    """
    first_window = scores["window_start"].min()
    last = scores["window_start"].max() + timedelta(seconds=window_seconds)
    if incidents.empty:
        return first_window.to_pydatetime(), last.to_pydatetime()
    start = max(incidents["start"].min() - lead, first_window)
    return start.to_pydatetime(), max(last, incidents["end"].max()).to_pydatetime()


def closed_incidents(incidents: pd.DataFrame, moment: datetime) -> pd.DataFrame:
    """Return the incidents with `end <= moment` (plan 9.1)."""
    return incidents[incidents["end"] <= moment]


def finished_windows(scores: pd.DataFrame, moment: datetime, window_seconds: int) -> pd.DataFrame:
    """Return the windows with `end <= moment`. A window ends one length after `window_start`."""
    return scores[scores["window_start"] + timedelta(seconds=window_seconds) <= moment]


def missing_reports(incidents: pd.DataFrame, reports: dict, attempted: set[str]) -> list[str]:
    """Return the closed incidents still without a report, in closing order, for `--live`.

    Args:
        incidents: Closed incidents.
        reports: Saved reports by incident.
        attempted: Incidents already tried, so that a failure is not paid for again and again.

    Returns:
        Incident ids.
    """
    ordered = incidents.sort_values(["end", "incident_id"])["incident_id"]
    return [item for item in ordered if item not in reports and item not in attempted]


def needs_rerun(follows_clock: bool, shown_closed: int, closed_now: int) -> bool:
    """Tell whether a tick must redraw the page.

    A page that does not draw windows changes only when an incident closes. Redrawing it on every
    tick would be wasted work, and on the Chat page it would disturb the conversation.

    Args:
        follows_clock: The page draws windows.
        shown_closed: Closed incidents on the page.
        closed_now: Closed incidents at this tick.

    Returns:
        True to redraw.
    """
    return follows_clock or shown_closed != closed_now
