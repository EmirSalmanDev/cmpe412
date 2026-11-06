"""Prompt files and the rendering of untrusted text (plan 7.4).

Log lines are attacker-influenced. Everything derived from them reaches the LLM inside one pair of
delimiters, and `wrap_untrusted` makes sure the text inside cannot contain those delimiters.
"""

import re
import unicodedata
from dataclasses import dataclass
from importlib import resources

DATA_OPEN = "<<<UNTRUSTED_LOG_DATA>>>"
DATA_CLOSE = "<<<END_UNTRUSTED_LOG_DATA>>>"
# Any spelling of the delimiter word; `\W` also takes zero-width characters.
DELIMITER_WORD = re.compile(r"untrusted[\W_]*log[\W_]*data", re.IGNORECASE)
REMOVED = "[delimiter text removed]"
HEADER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
ROLES = ("investigator", "mapper", "mapper_no_rag", "reporter", "verifier")


@dataclass(frozen=True)
class Prompt:
    """A prompt file."""

    version: str
    text: str


def wrap_untrusted(text: str) -> str:
    """Put untrusted text between the data delimiters.

    Args:
        text: Log lines, tool output or anything derived from them.

    Returns:
        The delimited text. Compatibility forms are normalized first, so that a look-alike
        spelling of the delimiter is caught as well.
    """
    clean = DELIMITER_WORD.sub(REMOVED, unicodedata.normalize("NFKC", text))
    return f"{DATA_OPEN}\n{clean}\n{DATA_CLOSE}"


def parse_prompt(source: str) -> Prompt:
    """Split a prompt file into its `prompt_version` header and body.

    Raises:
        ValueError: If the header or the word json is missing (plan 7.1).
    """
    match = HEADER.match(source)
    fields = dict(
        line.split(":", 1) for line in (match.group(1).splitlines() if match else []) if ":" in line
    )
    version = fields.get("prompt_version", "").strip()
    if not version:
        raise ValueError("a prompt needs a prompt_version header")
    text = source[match.end() :].strip()
    if "json" not in text.lower():
        raise ValueError(f"{version}: JSON mode needs the word json in the prompt")
    return Prompt(version, text)


def load_prompt(name: str) -> Prompt:
    """Read `prompts/<name>.md`."""
    package = resources.files("logtriage.agents") / "prompts"
    return parse_prompt((package / f"{name}.md").read_text(encoding="utf-8"))


def load_prompts(few_shot: bool = False) -> dict[str, Prompt]:
    """Read the prompt of every role.

    Args:
        few_shot: Append the Reporter examples (plan 7.4). Their text is written in M11.

    Returns:
        Role to prompt.

    Raises:
        FileNotFoundError: If `few_shot` is on and the examples do not exist yet.
    """
    prompts = {role: load_prompt(role) for role in ROLES}
    if few_shot:
        examples = load_prompt("reporter_examples")
        base = prompts["reporter"]
        prompts["reporter"] = Prompt(
            f"{base.version}+{examples.version}", f"{base.text}\n\n{examples.text}"
        )
    return prompts
