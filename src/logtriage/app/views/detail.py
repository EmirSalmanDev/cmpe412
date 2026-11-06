"""Incident detail page (plan 9.1): the score timeline and the report with its evidence."""

from datetime import timedelta

import streamlit as st

from logtriage.app import ui
from logtriage.app.charts import incident_streams, stream_windows, timeline_figure
from logtriage.app.data import AppOptions, technique_url

view = ui.get_view()
st.title("Incident detail")
incident_id = ui.pick_incident(view, "detail")
if incident_id is None:
    st.stop()

settings = ui.settings_of(str(AppOptions.from_env().config))
incident = view.incidents[view.incidents["incident_id"] == incident_id].iloc[0]
report = view.reports.get(incident_id)
st.text(
    f"{ui.utc(incident['start'])} to {ui.utc(incident['end'])} · "
    f"{', '.join(incident['hosts'])} · {', '.join(incident['log_types'])}"
)

st.subheader("Timeline")
streams = incident_streams(view.windows, incident_id)
context = timedelta(minutes=settings.app.timeline_context_minutes)
near = stream_windows(view.windows, streams, incident["start"], incident["end"], context)
figure = timeline_figure(
    near,
    streams,
    incident["start"],
    incident["end"],
    settings.ml.q,
    settings.features.window_seconds,
)
st.plotly_chart(figure, theme=None, key=f"timeline_{incident_id}")
st.caption(
    "Window scores of the streams of this incident. Diamonds are anomalous windows; "
    "the shaded span is the incident."
)
with st.expander("Windows as a table"):
    st.dataframe(near, hide_index=True)

if report is None:
    st.info("This incident has no report.")
    st.stop()

st.subheader("Report")
ui.verdict_badge(report.verdict, report.confidence)
st.markdown("**Summary**")
for claim in report.summary:
    ui.show_claim(claim, report)

st.markdown("**Timeline of events**")
for item in report.timeline:
    ui.show_claim(item.claim, report, prefix=f"{ui.utc(item.ts)} · ")

st.markdown("**ATT&CK techniques**")
if not report.techniques:
    st.text("No technique was mapped.")
for choice in report.techniques:
    st.link_button(
        choice.technique_id, technique_url(choice.technique_id), icon=":material/open_in_new:"
    )
    st.text(choice.name)
    ui.show_claim(choice.justification, report)

st.markdown("**Recommended actions**")
st.caption("Recommendations only. Nothing was changed on any system.")
for action in report.recommended_actions:
    st.text(f"• {action}")
