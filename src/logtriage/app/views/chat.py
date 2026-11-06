"""Chat page (plan 9.1, 7.5): questions on the selected incident, one thread each."""

import openai
import streamlit as st

from logtriage.agents.chat import thread_turns
from logtriage.agents.llm import BudgetExceededError
from logtriage.app import ui
from logtriage.app.data import AppOptions

view = ui.get_view()
st.title("Chat")
incident_id = ui.pick_incident(view, "chat")
if incident_id is None:
    st.stop()
if incident_id not in view.reports:
    st.info("This incident has no report, so there is nothing to chat about yet.")
    st.stop()

options = AppOptions.from_env()
config = str(options.config)
settings = ui.settings_of(config)
st.caption(
    "Each answer cites log lines. Code checks that every cited line exists, not that it shows "
    "what the claim says, so open the lines before you rely on a claim."
)
for turn in thread_turns(ui.memory_of(config), incident_id):
    ui.show_turn(turn)

has_key = settings.deepseek_api_key is not None
if not has_key:
    st.warning("DEEPSEEK_API_KEY is not set, so the chat can show its history but not answer.")
question = st.chat_input(f"Ask about {incident_id}", disabled=not has_key)
if question:
    agent = ui.chat_agent_of(options.testbed, config)
    try:
        with st.spinner("Thinking..."):
            agent.ask(incident_id, question)
    except BudgetExceededError as error:
        st.error(f"Stopped by a spending limit: {error}")
    except openai.APIError as error:
        st.error(f"The model could not be reached: {type(error).__name__}")
    else:
        st.rerun()
