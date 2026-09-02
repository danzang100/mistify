"""Building a provider from configuration.

Adapters are imported lazily. Constructing a `MistifyConfig`, running the ingest pipeline, or
importing anything under `mistify.llm` must not require a vendor SDK to be installed or a
credential to exist -- only actually asking for a provider does. That is what keeps the whole
deterministic half of this system runnable with no account anywhere.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mistify.common.config import LLMConfig
    from mistify.llm.base import LLMProvider

__all__ = ["MissingCredentialError", "build_provider"]


class MissingCredentialError(RuntimeError):
    """A provider was asked for but nothing on this machine can authenticate it."""


_GEMINI_HELP = (
    "No Gemini credential found. Set GEMINI_API_KEY, either in the environment or in a .env "
    "file at the repo root, which the CLI loads on startup. A free AI Studio key works; its "
    "per-minute quota is tight, so set llm.min_interval_seconds if you hit throttling. "
    "To work without any credential, run with --investigator skeleton, which uses the "
    "deterministic heuristic and calls no model."
)


def build_provider(name: str, model: str, config: LLMConfig) -> LLMProvider:
    """Construct the named provider.

    Raises `MissingCredentialError` rather than letting an SDK fail deep inside the first
    model call, because by then a scratchpad has been loaded and the failure looks like an
    investigation problem instead of a setup one.
    """
    if name == "scripted":
        raise MissingCredentialError(
            "The 'scripted' provider replays fixed turns and exists for tests. Configure a "
            "real provider, or run with --investigator skeleton."
        )

    if name == "gemini":
        import os

        if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
            raise MissingCredentialError(_GEMINI_HELP)
        from mistify.llm.gemini import GeminiProvider

        return GeminiProvider(
            model=model,
            min_interval_seconds=config.min_interval_seconds,
            timeout_seconds=config.request_timeout_seconds,
        )

    raise MissingCredentialError(f"unknown llm provider {name!r}. Known: gemini, scripted")
