"""Report and agent output models (plan 5.7, 7.4).

The LLM only ever sees and cites eids. Code resolves an eid to its `line_id`. An unknown eid is
not a validation error here: it has to reach the Verifier, and the count of the first draft, as an
unsupported claim (plan 10.2).
"""

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, Field


def as_utc(moment: datetime) -> datetime:
    """Return a time as tz-aware UTC. A time without a zone is taken as UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


UtcTime = Annotated[datetime, AfterValidator(as_utc)]
TechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]


class Evidence(BaseModel):
    """One log line a report may cite."""

    eid: str
    line_id: str
    ts: UtcTime
    host: str
    log_type: str
    raw: str
    note: str


class Claim(BaseModel):
    """A statement and the lines that support it."""

    text: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)


class TimelineItem(BaseModel):
    """One dated claim."""

    ts: UtcTime
    claim: Claim


class TechniqueChoice(BaseModel):
    """One ATT&CK technique of a report."""

    technique_id: TechniqueId
    name: str
    justification: Claim


class IncidentReport(BaseModel):
    """The final report. `summary` may be empty only after finalize removed every claim."""

    incident_id: str
    summary: list[Claim] = Field(max_length=4)
    timeline: list[TimelineItem]
    techniques: list[TechniqueChoice] = Field(max_length=3)
    verdict: Literal["malicious", "benign", "uncertain"]
    confidence: float = Field(ge=0, le=1)
    recommended_actions: list[str]
    evidence: list[Evidence]
    # Rewrites the Verifier asked for, at most `agents.max_rewrites`.
    verifier_rounds: int
    unsupported_claims_removed: list[str]
    meta: dict[str, Any]


class EvidencePick(BaseModel):
    """A line the Investigator keeps, and why."""

    eid: str
    note: str


class InvestigatorOutput(BaseModel):
    """Final answer of the Investigator."""

    behavior_summary: str = Field(min_length=1)
    evidence: list[EvidencePick] = Field(min_length=1)


class TechniquePick(BaseModel):
    """A technique as the Mapper and the Reporter return it; code adds the name."""

    technique_id: TechniqueId
    justification: Claim


class MapperOutput(BaseModel):
    """Final answer of the Mapper, ranked."""

    techniques: list[TechniquePick] = Field(max_length=3)


class ReportDraft(BaseModel):
    """What the Reporter writes; code adds the rest of `IncidentReport`."""

    summary: list[Claim] = Field(min_length=1, max_length=4)
    timeline: list[TimelineItem]
    techniques: list[TechniquePick] = Field(max_length=3)
    verdict: Literal["malicious", "benign", "uncertain"]
    confidence: float = Field(ge=0, le=1)
    recommended_actions: list[str]


class ClaimJudgment(BaseModel):
    """The Verifier's decision on one claim."""

    id: str
    reason: str
    verdict: Literal["supported", "unsupported"]


class VerifierOutput(BaseModel):
    """Answer of the Verifier for one round."""

    results: list[ClaimJudgment]


class UnsupportedClaim(BaseModel):
    """A claim that failed verification, and where it sits in the draft."""

    key: str
    text: str
    reason: str


def draft_claims(draft: ReportDraft) -> list[tuple[str, Claim, str]]:
    """List every claim of a draft.

    Args:
        draft: The draft.

    Returns:
        Key, claim and text to judge. A timeline claim is judged with its time.
    """
    claims = [(f"summary:{i}", claim, claim.text) for i, claim in enumerate(draft.summary)]
    claims += [
        (f"timeline:{i}", item.claim, f"At {item.ts:%Y-%m-%d %H:%M:%S} UTC: {item.claim.text}")
        for i, item in enumerate(draft.timeline)
    ]
    claims += [
        (
            f"technique:{i}",
            pick.justification,
            f"{pick.technique_id}: {pick.justification.text}",
        )
        for i, pick in enumerate(draft.techniques)
    ]
    return claims


def report_claims(report: IncidentReport) -> list[Claim]:
    """List every claim left in a final report."""
    return (
        list(report.summary)
        + [item.claim for item in report.timeline]
        + [choice.justification for choice in report.techniques]
    )
