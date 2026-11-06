"""Streamlit entry point (plan 9.1). Start it with `logtriage app`."""

import streamlit as st

from logtriage.app import ui
from logtriage.app.data import AppOptions, database_path
from logtriage.app.replay import check_live


def main() -> None:
    """Set up the page, the replay clock and the view, then run the selected page."""
    st.set_page_config(page_title="LogTriage", page_icon=":material/shield:", layout="wide")
    options = AppOptions.from_env()
    settings = ui.settings_of(str(options.config))
    path = database_path(settings, options.testbed)
    if not path.is_file():
        st.error(f"{options.testbed}: agent database not found. Run `logtriage prepare` first.")
        st.stop()
    dataset = ui.dataset_of(str(path))
    current = st.navigation(
        [
            st.Page("views/incidents.py", title="Incidents", icon=":material/list_alt:"),
            st.Page("views/detail.py", title="Incident detail", icon=":material/search:"),
            st.Page("views/chat.py", title="Chat", icon=":material/chat:"),
            st.Page("views/monitoring.py", title="Monitoring", icon=":material/monitoring:"),
        ]
    )
    st.sidebar.caption(f"Testbed: {options.testbed}")
    moment = ui.replay_sidebar(dataset, settings, follows_clock=current.title == "Incident detail")
    view = ui.current_view(options, settings, dataset, moment)
    if options.live and st.session_state.get("replay_on"):
        try:
            check_live(options.testbed)
        except ValueError as error:
            st.sidebar.error(str(error))
        else:
            ui.run_live(options, settings, view)
    current.run()


main()
