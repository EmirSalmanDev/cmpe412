"""Incidents page (plan 9.1): the table by priority."""

import streamlit as st

from logtriage.app import ui
from logtriage.app.data import incident_table

view = ui.get_view()
st.title("Incidents")
if view.incidents.empty:
    st.info("No incident has closed yet.")
    st.stop()

table = incident_table(view.incidents, view.reports)
left, middle, right = st.columns(3)
left.metric("Incidents", len(table))
middle.metric("Reports", len(view.reports))
right.metric("Malicious verdicts", int((table["verdict"] == "malicious").sum()))
selection = st.dataframe(
    table,
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    key="incident_table",
    column_config={
        "start": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
        "end": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
        "score": st.column_config.NumberColumn(format="%.4f"),
        "priority": st.column_config.NumberColumn(format="%.3f"),
        "confidence": st.column_config.NumberColumn(format="%.2f"),
    },
)
st.caption("Times are UTC. Select a row to open the incident.")
rows = selection.selection.rows
if rows:
    st.session_state[ui.SELECTED] = table.iloc[rows[0]]["incident"]
    st.switch_page("views/detail.py")
