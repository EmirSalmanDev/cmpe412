"""Monitoring page (plan 9.1): cost, latency, tokens and verifier rounds."""

import streamlit as st

from logtriage.app import ui
from logtriage.app.data import AppOptions, ledger_spend, monitoring_table, monitoring_totals

view = ui.get_view()
st.title("Monitoring")
if not view.reports:
    st.info("No report has been revealed yet.")
    st.stop()

settings = ui.settings_of(str(AppOptions.from_env().config))
table = monitoring_table(view.reports)
totals = monitoring_totals(table)
count = len(table)

st.subheader("Totals of the reports shown")
cost, latency, tokens, calls = st.columns(4)
cost.metric("Cost", f"{totals['cost_usd']:.4f} USD")
cost.caption(f"{totals['cost_usd'] / count:.4f} USD per report")
latency.metric("Latency", f"{totals['latency_s']:.1f} s")
latency.caption(f"{totals['latency_s'] / count:.1f} s per report")
tokens.metric("Tokens in / out", f"{totals['tokens_in']:,.0f} / {totals['tokens_out']:,.0f}")
tokens.caption(f"{totals['tokens_cached']:,.0f} input tokens cached")
calls.metric("LLM calls", f"{totals['llm_calls']:.0f}")

st.subheader("Per incident")
st.dataframe(
    table,
    hide_index=True,
    column_config={
        "cost_usd": st.column_config.NumberColumn(format="%.4f"),
        "latency_s": st.column_config.NumberColumn(format="%.1f"),
    },
)

spend = ledger_spend(settings)
st.subheader("Spending ledger")
paid, chat, limit = st.columns(3)
paid.metric("Paid over all runs", f"{spend['total']:.4f} USD")
chat.metric("Of which chat", f"{spend['chat']:.4f} USD")
limit.metric("Limit", f"{settings.llm.max_usd_total:.2f} USD")
st.caption(
    "Report cost includes answers replayed from the cache; the ledger holds only real payments."
)
