"""The Gemini adapter, tested without a credential or a network.

Every test injects a fake client through the `client=` constructor argument, so nothing here
reads `GEMINI_API_KEY` or reaches the API. The fake records the `model`, `contents` and
`config` it was handed, which is what makes the *request* side assertable: the translation
into Gemini's shape is the only thing this project owns on that side of the seam.

The behaviours pinned here are the ones where a plausible-looking translation produces a loop
that runs and is wrong -- tool use hidden behind a `STOP` finish reason, a dropped thought
signature that 400s the whole request, a tool result addressed by id to an API that matches on
name. Each of those is cheap to break and expensive to notice.

Per the convention in this suite, every assert-a-negative is paired with a control: a test
that would fail if the thing being asserted absent were present, or a sibling value that must
survive the same operation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import pytest
from google.genai import types

from mistify.llm.base import (
    LLMProvider,
    Message,
    ProviderError,
    ToolCall,
    ToolResult,
    ToolSpec,
    Usage,
)
from mistify.llm.gemini import GeminiProvider, _advertised_delay

MODEL = "gemini-3-pro-preview"

SEARCH_TOOL = ToolSpec(
    name="search_logs",
    description="Search the log slice.",
    schema={"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
)

#: A schema with `additionalProperties` at three depths -- top level, a nested object, and the
#: item schema of an array -- plus one of every keyword that must survive sanitisation.
NESTED_TOOL = ToolSpec(
    name="query_rows",
    description="Query the ingested rows.",
    schema={
        "type": "object",
        "description": "Query arguments.",
        "additionalProperties": False,
        "properties": {
            "table": {
                "type": "string",
                "description": "Which table to read.",
                "enum": ["events", "clusters"],
            },
            "filters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"level": {"type": "string"}},
                "required": ["level"],
            },
            "columns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"name": {"type": "string"}},
                },
            },
        },
        "required": ["table"],
    },
)


# ------------------------------------------------------------------ fake SDK responses


@dataclass
class _FunctionCall:
    """The `function_call` payload the adapter reads off a part."""

    name: str
    args: dict[str, Any] | None = None


@dataclass
class _Part:
    """One response part, exposing only the attributes the adapter reads with `getattr`."""

    text: str | None = None
    function_call: _FunctionCall | None = None
    thought_signature: bytes | None = None


@dataclass
class _Content:
    parts: list[_Part] = field(default_factory=list)


@dataclass
class _Candidate:
    content: _Content | None = None
    finish_reason: Any = "STOP"


@dataclass
class _UsageMetadata:
    prompt_token_count: int | None = 0
    candidates_token_count: int | None = 0
    cached_content_token_count: int | None = 0


@dataclass
class _Response:
    candidates: list[_Candidate] | None = None
    usage_metadata: _UsageMetadata | None = field(default_factory=_UsageMetadata)


def _response(
    *parts: _Part,
    finish_reason: Any = "STOP",
    usage: _UsageMetadata | None = None,
) -> _Response:
    """A one-candidate response carrying `parts`."""
    return _Response(
        candidates=[_Candidate(content=_Content(parts=list(parts)), finish_reason=finish_reason)],
        usage_metadata=usage if usage is not None else _UsageMetadata(),
    )


def _text(text: str) -> _Part:
    return _Part(text=text)


def _call(name: str, args: dict[str, Any] | None = None, signature: bytes | None = None) -> _Part:
    return _Part(function_call=_FunctionCall(name=name, args=args), thought_signature=signature)


# ------------------------------------------------------------------ fake client


@dataclass
class _SentCall:
    """What the adapter handed the SDK for one request."""

    model: str
    contents: list[Any]
    config: Any


class _Models:
    """Stands in for `client.models`."""

    def __init__(self, client: _FakeClient) -> None:
        self._client = client

    def generate_content(self, *, model: str, contents: list[Any], config: Any) -> Any:
        self._client.calls.append(_SentCall(model=model, contents=contents, config=config))
        outcome = self._client.outcome_for(len(self._client.calls) - 1)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _FakeClient:
    """Returns one canned outcome per call, repeating the last once the script runs out.

    Outcomes may be responses or exceptions, which is what lets the retry tests describe a
    failure that clears on the third attempt without any waiting or any network.
    """

    def __init__(self, *outcomes: Any) -> None:
        self.calls: list[_SentCall] = []
        self._outcomes: list[Any] = list(outcomes) or [_response(_text("ok"))]
        self.models = _Models(self)

    def outcome_for(self, index: int) -> Any:
        return self._outcomes[min(index, len(self._outcomes) - 1)]

    @property
    def last(self) -> _SentCall:
        return self.calls[-1]


class _Sleeps:
    """An injected `sleep` that records instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def _provider(*outcomes: Any, **kwargs: Any) -> GeminiProvider:
    return GeminiProvider(MODEL, client=_FakeClient(*outcomes), **kwargs)


def _client_of(provider: GeminiProvider) -> _FakeClient:
    client = provider.client
    assert isinstance(client, _FakeClient)
    return client


def _ask(provider: GeminiProvider, **kwargs: Any) -> Any:
    """The minimal conversation, so tests only spell out the part they are about."""
    return provider.converse("system", [Message(role="user", text="go")], **kwargs)


# ------------------------------------------------------------------ the seam itself


def test_the_adapter_satisfies_the_provider_protocol() -> None:
    assert isinstance(_provider(), LLMProvider)


def test_the_adapter_identifies_itself_and_its_model() -> None:
    """A conclusion has to be traceable to what produced it, so both are carried."""
    provider = _provider()
    assert provider.name == "gemini"
    assert provider.model == MODEL
    assert _client_of(provider) is provider.client


def test_constructing_the_provider_needs_no_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """An injected client must short-circuit key lookup entirely, not merely usually."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    turn = _ask(_provider(_response(_text("done"))))

    assert turn.text == "done"


def test_no_credential_and_no_client_is_a_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the test above: without the injected client, the lookup does happen."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    provider = GeminiProvider(MODEL)

    with pytest.raises(ProviderError, match="No Gemini credential found"):
        _ask(provider)


# ------------------------------------------------------------------ tool use is in the parts


def test_a_function_call_part_means_tool_use_even_though_gemini_says_stop() -> None:
    """The single most important behaviour in this adapter.

    Gemini returns `STOP` whether or not it asked for a tool. Mapping the finish reason
    straight onto the seam's `StopReason` would report every tool request as a finished answer
    and end every investigation on its first tool call.
    """
    turn = _ask(_provider(_response(_call("search_logs", {"q": "timeout"}), finish_reason="STOP")))

    assert turn.stop_reason == "tool_use"
    assert turn.stop_reason != "end_turn"
    assert turn.wants_tools
    assert turn.tool_calls[0].name == "search_logs"
    assert turn.tool_calls[0].arguments == {"q": "timeout"}


def test_the_same_finish_reason_without_a_call_part_is_end_turn() -> None:
    """Control for the test above: `STOP` is not being hard-coded to `tool_use`.

    The two tests differ only in whether a `function_call` part is present, which is exactly
    the claim -- parts decide, the finish reason does not.
    """
    turn = _ask(_provider(_response(_text("Root cause: pool exhaustion."), finish_reason="STOP")))

    assert turn.stop_reason == "end_turn"
    assert not turn.wants_tools


def test_text_and_a_call_can_arrive_in_the_same_turn() -> None:
    provider = _provider(_response(_text("Checking the pool."), _call("search_logs", {"q": "x"})))

    turn = _ask(provider)

    assert turn.text == "Checking the pool."
    assert turn.stop_reason == "tool_use"
    assert len(turn.tool_calls) == 1


def test_parallel_calls_keep_distinct_ids() -> None:
    """The seam addresses a result by id, so two calls in one turn must not share one."""
    provider = _provider(
        _response(_call("search_logs", {"q": "timeout"}), _call("search_logs", {"q": "retry"}))
    )

    turn = _ask(provider)

    assert len({call.id for call in turn.tool_calls}) == 2
    assert [call.arguments["q"] for call in turn.tool_calls] == ["timeout", "retry"]


def test_a_call_with_no_arguments_decodes_to_an_empty_dict() -> None:
    """The live API sends `args=None` for a no-argument tool; the seam promises a dict."""
    turn = _ask(_provider(_response(_call("list_tables", None))))

    assert turn.tool_calls[0].arguments == {}


@pytest.mark.parametrize(
    ("finish_reason", "expected"),
    [
        ("STOP", "end_turn"),
        ("MAX_TOKENS", "max_tokens"),
        ("SAFETY", "refusal"),
        ("PROHIBITED_CONTENT", "refusal"),
        ("BLOCKLIST", "refusal"),
        (types.FinishReason.MAX_TOKENS, "max_tokens"),
        (types.FinishReason.SAFETY, "refusal"),
        (None, "end_turn"),
    ],
)
def test_finish_reasons_map_when_no_tool_was_asked_for(finish_reason: Any, expected: str) -> None:
    """Including the SDK's enum, whose `str()` is `FinishReason.SAFETY` rather than `SAFETY`."""
    turn = _ask(_provider(_response(_text("x"), finish_reason=finish_reason)))
    assert turn.stop_reason == expected


def test_a_tool_call_outranks_even_a_truncating_finish_reason() -> None:
    """A truncated turn that still asked for a tool is a tool call the caller must dispatch."""
    provider = _provider(_response(_call("search_logs", {"q": "x"}), finish_reason="MAX_TOKENS"))
    assert _ask(provider).stop_reason == "tool_use"


# ------------------------------------------------------------------ thought signatures


def test_a_thought_signature_on_a_part_lands_on_the_tool_call() -> None:
    """Gemini 3 attaches an opaque signature to a call and demands it back verbatim."""
    provider = _provider(_response(_call("search_logs", {"q": "x"}, signature=b"sig-alpha")))

    turn = _ask(provider)

    assert turn.tool_calls[0].signature == b"sig-alpha"


def test_a_call_without_a_signature_carries_none() -> None:
    """Control: the field is read off the part, not manufactured."""
    turn = _ask(_provider(_response(_call("search_logs", {"q": "x"}))))
    assert turn.tool_calls[0].signature is None


def test_a_replayed_call_sends_its_thought_signature_back_verbatim() -> None:
    """Without the signature the API rejects the whole request with 400 INVALID_ARGUMENT.

    Two calls with different signatures, so the test fails if the adapter attaches a constant,
    the wrong one, or the same one to both parts.
    """
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="go"),
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="a", name="search_logs", arguments={}, signature=b"sig-alpha"),
                    ToolCall(id="b", name="count_rows", arguments={}, signature=b"sig-beta"),
                ),
            ),
        ],
    )

    parts = _client_of(provider).last.contents[1].parts
    assert [part.thought_signature for part in parts] == [b"sig-alpha", b"sig-beta"]
    assert [part.function_call.name for part in parts] == ["search_logs", "count_rows"]


def test_a_signature_survives_a_full_round_trip_through_the_seam() -> None:
    """Decode then re-encode, since the round trip is what the API actually checks."""
    provider = _provider(_response(_call("search_logs", {"q": "x"}, signature=b"sig-round")))
    turn = _ask(provider)

    provider.converse(
        "system",
        [
            Message(role="user", text="go"),
            Message(role="assistant", tool_calls=turn.tool_calls),
        ],
    )

    assert _client_of(provider).last.contents[1].parts[0].thought_signature == b"sig-round"


def test_a_replayed_call_without_a_signature_sends_none() -> None:
    """Control for the round trip: the outgoing value tracks the `ToolCall`, not a default."""
    provider = _provider()
    provider.converse(
        "system",
        [Message(role="assistant", tool_calls=(ToolCall(id="a", name="f", arguments={}),))],
    )

    assert _client_of(provider).last.contents[0].parts[0].thought_signature is None


# ------------------------------------------------------------------ schema sanitisation


def _declared_schema(provider: GeminiProvider) -> Any:
    declarations = _client_of(provider).last.config.tools[0].function_declarations
    assert len(declarations) == 1
    return declarations[0].parameters


def test_additional_properties_is_stripped_at_every_depth() -> None:
    """The function-declaration parser rejects `additionalProperties` outright.

    Recursion matters as much as the top level: a nested object or an array item schema
    carrying it fails the request just as hard, and the failure names the whole tool.
    """
    provider = _provider()
    _ask(provider, tools=[NESTED_TOOL])

    schema = _declared_schema(provider)
    assert schema.additional_properties is None
    assert schema.properties["filters"].additional_properties is None
    assert schema.properties["columns"].items.additional_properties is None


def test_the_unsanitised_schema_would_have_carried_it_through() -> None:
    """Control for the test above, which would otherwise pass on a schema type that drops it.

    The SDK's `Schema` keeps `additionalProperties` at all three depths, so the assertions in
    the stripping test are about the adapter's work rather than the SDK's.
    """
    raw = types.Schema(**NESTED_TOOL.schema)

    assert raw.additional_properties is False
    assert raw.properties is not None
    assert raw.properties["filters"].additional_properties is False
    assert raw.properties["columns"].items is not None
    assert raw.properties["columns"].items.additional_properties is False


def test_every_other_schema_keyword_survives_sanitisation() -> None:
    """Sanitisation is a deny list, not a rewrite into Gemini's dialect.

    Dropping `enum` or `required` while stripping the one bad key would silently widen every
    tool's contract, which shows up as the model passing arguments the tool cannot handle.
    """
    provider = _provider()
    _ask(provider, tools=[NESTED_TOOL])

    schema = _declared_schema(provider)
    assert schema.type == types.Type.OBJECT
    assert schema.description == "Query arguments."
    assert schema.required == ["table"]
    assert set(schema.properties) == {"table", "filters", "columns"}
    assert schema.properties["table"].enum == ["events", "clusters"]
    assert schema.properties["table"].description == "Which table to read."
    assert schema.properties["table"].type == types.Type.STRING
    assert schema.properties["filters"].required == ["level"]
    assert schema.properties["columns"].type == types.Type.ARRAY
    assert schema.properties["columns"].items.properties["name"].type == types.Type.STRING


def test_the_declaration_carries_the_tool_name_and_description() -> None:
    provider = _provider()
    _ask(provider, tools=[SEARCH_TOOL])

    declaration = _client_of(provider).last.config.tools[0].function_declarations[0]
    assert declaration.name == "search_logs"
    assert declaration.description == "Search the log slice."


def test_several_tools_arrive_in_one_declaration_block() -> None:
    provider = _provider()
    _ask(provider, tools=[SEARCH_TOOL, NESTED_TOOL])

    tools = _client_of(provider).last.config.tools
    assert len(tools) == 1
    assert [d.name for d in tools[0].function_declarations] == ["search_logs", "query_rows"]


def test_no_tools_means_no_tool_config_at_all() -> None:
    """Paired with the test above: an empty declaration list is not the same as none."""
    provider = _provider()
    _ask(provider)
    assert _client_of(provider).last.config.tools is None

    empty = _provider()
    _ask(empty, tools=[])
    assert _client_of(empty).last.config.tools is None


# ------------------------------------------------------------------ roles and message shape


def test_assistant_becomes_model_and_user_stays_user() -> None:
    """The seam says `assistant`; Gemini only accepts `user` and `model`."""
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="investigate"),
            Message(role="assistant", text="Looking."),
            Message(role="user", text="anything else?"),
        ],
    )

    contents = _client_of(provider).last.contents
    assert [content.role for content in contents] == ["user", "model", "user"]
    assert contents[1].parts[0].text == "Looking."


def test_a_message_with_nothing_in_it_is_dropped() -> None:
    """Gemini rejects a `Content` with no parts, and the caller does emit empty turns.

    Paired with the surviving neighbours: the drop is one message, not a truncation.
    """
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="one"),
            Message(role="assistant"),
            Message(role="user", text="two"),
        ],
    )

    contents = _client_of(provider).last.contents
    assert len(contents) == 2
    assert [content.parts[0].text for content in contents] == ["one", "two"]


def test_the_system_prompt_travels_as_a_system_instruction() -> None:
    provider = _provider()
    _ask(provider)
    assert _client_of(provider).last.config.system_instruction == "system"


def test_an_empty_system_prompt_becomes_none_rather_than_an_empty_string() -> None:
    """Control for the test above. The API rejects an empty instruction string."""
    provider = _provider()
    provider.converse("", [Message(role="user", text="go")])
    assert _client_of(provider).last.config.system_instruction is None


def test_the_model_name_is_sent_on_every_call() -> None:
    provider = _provider()
    _ask(provider)
    assert _client_of(provider).last.model == MODEL


# ------------------------------------------------------------------ function responses


def test_a_tool_result_is_keyed_by_the_name_of_the_call_it_answers() -> None:
    """Gemini matches a response to a call by function name; the seam addresses it by id.

    The adapter rebuilds the id-to-name map by walking the conversation, so a history it did
    not produce still translates. Two different tools here, so answering with the wrong one's
    name fails the test.
    """
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(role="user", text="go"),
            Message(
                role="assistant",
                tool_calls=(
                    ToolCall(id="call-a", name="search_logs", arguments={"q": "timeout"}),
                    ToolCall(id="call-b", name="count_rows", arguments={}),
                ),
            ),
            Message(
                role="user",
                tool_results=(
                    ToolResult(call_id="call-b", content="41"),
                    ToolResult(call_id="call-a", content="3 rows"),
                ),
            ),
        ],
    )

    parts = _client_of(provider).last.contents[2].parts
    assert [part.function_response.name for part in parts] == ["count_rows", "search_logs"]
    assert [part.function_response.response for part in parts] == [
        {"result": "41"},
        {"result": "3 rows"},
    ]


def test_an_unknown_call_id_is_used_as_the_function_name() -> None:
    """Pinning the fallback, which is a guess rather than a guarantee.

    When the history holds no call with that id there is no name to look up, so the id goes
    out as the name. It only works when the caller happens to have used the tool name as the
    id; otherwise the API sees a function it never declared. Paired with the test above so the
    lookup path is proven to work when the call *is* present.
    """
    provider = _provider()
    provider.converse(
        "system",
        [Message(role="user", tool_results=(ToolResult(call_id="ghost-7", content="x"),))],
    )

    part = _client_of(provider).last.contents[0].parts[0]
    assert part.function_response.name == "ghost-7"


def test_an_error_result_and_a_successful_one_have_different_payloads() -> None:
    """A failed tool must not read as a result the model can reason from.

    Both are asserted in one test because the pair is the point: `error` and `result` have to
    differ, and asserting only one of them would pass on an adapter that used the same key for
    both.
    """
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(
                role="assistant",
                tool_calls=(ToolCall(id="call-a", name="search_logs", arguments={}),),
            ),
            Message(
                role="user",
                tool_results=(
                    ToolResult(call_id="call-a", content="3 rows"),
                    ToolResult(call_id="call-a", content="no such table", is_error=True),
                ),
            ),
        ],
    )

    parts = _client_of(provider).last.contents[1].parts
    assert parts[0].function_response.response == {"result": "3 rows"}
    assert parts[1].function_response.response == {"error": "no such table"}


def test_text_leads_a_message_that_also_carries_results() -> None:
    provider = _provider()
    provider.converse(
        "system",
        [
            Message(
                role="user",
                text="Anything else?",
                tool_results=(ToolResult(call_id="call-a", content="3 rows"),),
            )
        ],
    )

    parts = _client_of(provider).last.contents[0].parts
    assert parts[0].text == "Anything else?"
    assert parts[1].function_response is not None


# ------------------------------------------------------------------ automatic function calling


def test_automatic_function_calling_is_disabled() -> None:
    """We run the loop; the SDK must not.

    Left enabled, the SDK executes tools itself and returns only the final answer, which takes
    the audit trail, the tool-call budget and the forced-convergence path out of our hands --
    and does it silently, because the turns that vanish are the ones nobody sees.
    """
    provider = _provider()
    _ask(provider)

    assert _client_of(provider).last.config.automatic_function_calling.disable is True


def test_the_sdk_leaves_automatic_function_calling_on_by_default() -> None:
    """Control: the disable above is the adapter's doing, not the SDK's default."""
    assert types.GenerateContentConfig().automatic_function_calling is None


# ------------------------------------------------------------------ task budgets


def test_task_budgets_are_not_supported() -> None:
    """Declared rather than assumed, so the caller falls back to its own tool-call cap."""
    assert GeminiProvider.supports_task_budget is False
    assert _provider().supports_task_budget is False


def test_a_task_budget_is_ignored_rather_than_sent() -> None:
    """An unknown field would be rejected by the API, so it is dropped, not translated.

    `max_tokens` is asserted in the same dump as the control: it proves the search would have
    found the budget had the adapter forwarded it.
    """
    provider = _provider()
    _ask(provider, max_tokens=4096, task_budget_tokens=40_000)

    dumped = repr(_client_of(provider).last.config.model_dump(exclude_none=True))
    assert "4096" in dumped
    assert "40000" not in dumped


def test_max_tokens_reaches_the_config_as_the_output_ceiling() -> None:
    provider = _provider()
    _ask(provider, max_tokens=1234)
    assert _client_of(provider).last.config.max_output_tokens == 1234


# ------------------------------------------------------------------ no candidates


def test_a_response_with_no_candidates_is_a_refusal() -> None:
    """A blocked response is not an empty answer.

    Reporting it as `end_turn` would present a refusal as a finished conclusion, and the
    report would carry no sign that the model never actually answered.
    """
    provider = _provider(_Response(candidates=[], usage_metadata=_UsageMetadata(11, 0, 0)))

    turn = _ask(provider)

    assert turn.stop_reason == "refusal"
    assert turn.stop_reason != "end_turn"
    assert turn.text == ""
    assert not turn.wants_tools
    # Blocked prompts are still billed, so the usage still has to be reported.
    assert turn.usage == Usage(input_tokens=11)


def test_a_missing_candidates_attribute_is_also_a_refusal() -> None:
    """The live SDK omits the field entirely rather than sending an empty list."""
    assert _ask(_provider(_Response(candidates=None))).stop_reason == "refusal"


def test_one_candidate_with_the_same_shape_is_not_a_refusal() -> None:
    """Control: `refusal` comes from the empty candidate list, not from anything else here."""
    turn = _ask(_provider(_response(_text("answer"))))

    assert turn.stop_reason == "end_turn"
    assert turn.text == "answer"


def test_a_candidate_with_no_content_yields_an_empty_turn() -> None:
    """A candidate carrying no parts still ended the turn; it is not a block."""
    provider = _provider(_Response(candidates=[_Candidate(content=None)]))

    turn = _ask(provider)

    assert turn.text == ""
    assert turn.stop_reason == "end_turn"


# ------------------------------------------------------------------ usage


def test_usage_maps_prompt_candidate_and_cached_counts() -> None:
    provider = _provider(
        _response(
            _text("x"),
            usage=_UsageMetadata(
                prompt_token_count=1200, candidates_token_count=340, cached_content_token_count=900
            ),
        )
    )

    assert _ask(provider).usage == Usage(
        input_tokens=1200, output_tokens=340, cached_input_tokens=900
    )


def test_missing_usage_metadata_is_zero_rather_than_a_crash() -> None:
    """The live API omits it on some blocked responses."""
    response = _Response(candidates=[_Candidate(_Content([_text("x")]))], usage_metadata=None)
    provider = _provider(response)
    assert _ask(provider).usage == Usage()


def test_none_valued_usage_fields_are_zero_rather_than_a_crash() -> None:
    """The live API sends `candidates_token_count=None` when nothing was generated."""
    empty = _UsageMetadata(
        prompt_token_count=None, candidates_token_count=None, cached_content_token_count=None
    )
    provider = _provider(_response(_text("x"), usage=empty))
    assert _ask(provider).usage == Usage()


def test_a_populated_usage_is_not_silently_zeroed() -> None:
    """Control for the two tests above, which would both pass on an adapter returning `Usage()`."""
    provider = _provider(_response(_text("x"), usage=_UsageMetadata(prompt_token_count=7)))
    assert _ask(provider).usage != Usage()


# ------------------------------------------------------------------ retry and backoff


class _Boom(Exception):
    """A transport failure whose message carries the API's status text."""


class _ResourceExhausted(Exception):
    """A typed SDK error whose message says nothing useful, as the real ones often do not."""


@pytest.mark.parametrize(
    "error",
    [
        _Boom("429 RESOURCE_EXHAUSTED: quota exceeded"),
        _Boom("503 UNAVAILABLE: the model is overloaded"),
        _Boom("504 DEADLINE_EXCEEDED"),
        _ResourceExhausted("please try again"),
    ],
)
def test_a_retryable_failure_is_retried_and_can_succeed(error: Exception) -> None:
    """Free-tier quota is tight enough that a 429 mid-investigation is routine, not exceptional.

    The last case is matched on the exception's type name rather than its message, which is
    how the SDK's own typed errors arrive.
    """
    sleeps = _Sleeps()
    provider = _provider(error, error, _response(_text("recovered")), sleep=sleeps)

    turn = _ask(provider)

    assert turn.text == "recovered"
    assert len(_client_of(provider).calls) == 3
    assert len(sleeps.delays) == 2


def test_a_non_retryable_failure_raises_without_a_second_attempt() -> None:
    """A malformed request will be malformed again; retrying only delays the error.

    Paired with the retry test above, which shares this fake and this construction and differs
    only in the error text -- so this test fails if the adapter stops retrying anything.
    """
    sleeps = _Sleeps()
    provider = _provider(_Boom("400 INVALID_ARGUMENT: unknown field"), sleep=sleeps)

    with pytest.raises(ProviderError, match="Gemini call failed"):
        _ask(provider)

    assert len(_client_of(provider).calls) == 1
    assert sleeps.delays == []


def test_exhausting_the_retries_raises_and_keeps_the_cause() -> None:
    """The original error is the only thing that says *why*, so it is chained, not flattened."""
    sleeps = _Sleeps()
    error = _Boom("429 RESOURCE_EXHAUSTED")
    provider = _provider(error, max_retries=2, sleep=sleeps)

    with pytest.raises(ProviderError) as caught:
        _ask(provider)

    # One initial attempt plus `max_retries` retries, and a sleep between each pair.
    assert len(_client_of(provider).calls) == 3
    assert len(sleeps.delays) == 2
    assert caught.value.__cause__ is error


def test_max_retries_zero_means_one_attempt() -> None:
    """Control for the count above: the attempt total tracks `max_retries`, it is not fixed."""
    sleeps = _Sleeps()
    provider = _provider(_Boom("429"), max_retries=0, sleep=sleeps)

    with pytest.raises(ProviderError):
        _ask(provider)

    assert len(_client_of(provider).calls) == 1
    assert sleeps.delays == []


def test_the_backoff_grows_between_attempts() -> None:
    """Bounds rather than values, because the delay is jittered.

    Full jitter draws attempt `n` from `[0.5 * 2**n, 2**n)`, and those windows do not overlap,
    so growth is assertable without pinning the jitter. A fixed schedule would march a loop's
    own retries into the next rate-limit window together, which is why the jitter is there.
    """
    random.seed(20260901)
    sleeps = _Sleeps()
    provider = _provider(_Boom("503 UNAVAILABLE"), max_retries=4, sleep=sleeps)

    with pytest.raises(ProviderError):
        _ask(provider)

    assert len(sleeps.delays) == 4
    assert sleeps.delays == sorted(sleeps.delays)
    assert len(set(sleeps.delays)) == 4
    for attempt, delay in enumerate(sleeps.delays):
        assert 0.5 * 2**attempt <= delay < 2**attempt


def test_the_backoff_is_capped() -> None:
    """Otherwise the eighth retry would park the investigation for four minutes."""
    sleeps = _Sleeps()
    provider = _provider(_Boom("503 UNAVAILABLE"), max_retries=9, sleep=sleeps)

    with pytest.raises(ProviderError):
        _ask(provider)

    assert max(sleeps.delays) < 30
    assert len(sleeps.delays) == 9


# ------------------------------------------------------------------ pacing


def test_calls_are_spaced_out_when_an_interval_is_configured() -> None:
    """A caller who knows their per-minute quota can trade wall clock for never being throttled."""
    sleeps = _Sleeps()
    provider = _provider(min_interval_seconds=60.0, sleep=sleeps)

    _ask(provider)
    _ask(provider)

    assert len(sleeps.delays) == 1
    assert 0 < sleeps.delays[0] <= 60.0


def test_no_interval_means_no_pacing_sleep() -> None:
    """Control: the default leaves pacing to the retry path, which is faster when quota allows."""
    sleeps = _Sleeps()
    provider = _provider(sleep=sleeps)

    _ask(provider)
    _ask(provider)

    assert sleeps.delays == []


def test_the_servers_own_retry_delay_is_honoured() -> None:
    """Free-tier quotas are per-minute, and the API says exactly how long is left.

    Backing off on an exponential guess that tops out below that guarantees the next attempt
    fails too, which is how a whole retry budget gets spent inside one window that had not
    reset. Three of five runs failed this way before the delay was read.
    """
    sleeps = _Sleeps()
    quota = _Boom("429 RESOURCE_EXHAUSTED ... 'retryDelay': '54s'")
    provider = _provider(quota, _response(_text("recovered")), sleep=sleeps)

    assert _ask(provider).text == "recovered"
    assert sleeps.delays[0] >= 54.0


def test_a_retry_without_an_advertised_delay_uses_the_backoff() -> None:
    """Control: the server's number replaces the guess, it is not required for one to exist."""
    sleeps = _Sleeps()
    provider = _provider(_Boom("503 UNAVAILABLE"), _response(_text("recovered")), sleep=sleeps)

    assert _ask(provider).text == "recovered"
    assert 0 < sleeps.delays[0] <= 1.0


def test_the_advertised_delay_is_read_from_either_quoting_style() -> None:
    """The SDK stringifies the error dict; the JSON on the wire is quoted differently."""
    assert _advertised_delay(Exception("{'retryDelay': '54s'}")) == 54.0
    assert _advertised_delay(Exception('{"retryDelay": "7.5s"}')) == 7.5
    assert _advertised_delay(Exception("503 UNAVAILABLE")) is None


def test_the_timeout_is_converted_to_milliseconds() -> None:
    """A request with no ceiling does not fail, it hangs.

    One run sat in a single call for over thirty minutes at zero CPU, its search already
    finished, because nothing bounded the wait. The retry path already treats the resulting
    DEADLINE_EXCEEDED as retryable -- it was simply unreachable.

    The conversion is worth pinning on its own: the SDK takes milliseconds, and getting the
    factor wrong gives either a 120-millisecond timeout that fails every call or a
    120,000-second one that fails none.
    """
    from mistify.llm.gemini import http_options

    assert http_options(45).timeout == 45_000
    assert http_options(0.5).timeout == 500


def test_the_provider_keeps_the_timeout_it_was_given() -> None:
    """Config carries it, so a slow deployment raises the ceiling without a code change."""
    assert GeminiProvider(model=MODEL, timeout_seconds=30).timeout_seconds == 30
