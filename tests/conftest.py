"""Safety net of the test suite: only tests marked `live` may reach a real LLM."""

import pytest

from logtriage.agents.llm import DeepSeekChat


@pytest.fixture(autouse=True)
def no_real_llm(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any other test that gets as far as sending a request to the model.

    A CLI test once ran a real santos investigation, because `investigate` stopped being a stub
    while `.env` held a key (D47). This blocks the one path every real call takes.
    """
    if request.node.get_closest_marker("live"):
        return

    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("a test without @pytest.mark.live reached the real LLM")

    monkeypatch.setattr(DeepSeekChat, "_generate", refuse)
