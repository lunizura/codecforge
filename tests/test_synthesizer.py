from __future__ import annotations

import copy
import io
import json
from typing import Any
from unittest.mock import patch

import pytest

from codecforge.errors import CodecForgeError, SynthesisError
from codecforge.llm_client import (
    GeminiInteractionsProvider,
    OpenAICompatibleProvider,
    ScriptedMockProvider,
    extract_json_object,
)
from codecforge.oracle import verify_codec
from codecforge.runtime import decode_bytes, encode_obj
from codecforge.schema import CodecSpec, FieldSpec
from codecforge.synthesizer import synthesize_codec, synthesize_heuristic
from tests.fixtures import (
    make_fixed_header_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def test_heuristic_synthesizes_simple_save_and_passes_oracle() -> None:
    samples, truth_spec = make_simple_save_samples()
    spec, oracle = synthesize_codec(samples, provider_name="heuristic", name="simple_save")
    assert oracle.passed, oracle.failures
    assert spec.endian == "le"
    assert spec.fields[0].kind == "magic"
    assert spec.fields[0].magic_hex == "53415631"
    assert any(f.kind == "var_str" for f in spec.fields)
    assert any(f.scalar_type == "f32le" for f in spec.fields)
    assert spec.fields[-1].crc32_of is not None

    decoded, _ = decode_bytes(spec, samples[1])
    truth_obj, _ = decode_bytes(truth_spec, samples[1])
    assert any(v == truth_obj["bio"] for v in decoded.values())


def test_heuristic_synthesizes_fixed_header_and_passes_oracle() -> None:
    samples, _ = make_fixed_header_samples()
    spec = synthesize_heuristic(samples, name="fixed_header")
    oracle = verify_codec(spec, samples)
    assert oracle.passed, oracle.failures
    assert spec.fields[0].kind == "magic"
    assert spec.fields[-1].crc32_of is not None


def test_mock_llm_multi_round_self_healing() -> None:
    samples, truth_spec = make_rpg_save_samples()

    # Round 1: lazy bytes_rest (fails Gate 2)
    round1 = CodecSpec(
        name="rpg_save",
        fields=[FieldSpec(name="blob", kind="bytes_rest")],
    ).to_dict()

    # Round 2: missing length_of on name_len (passes Gate 1 & 2, fails Gate 3!)
    round2_spec = copy.deepcopy(truth_spec)
    round2_spec.fields[3].length_of = None
    round2 = round2_spec.to_dict()

    # Round 3: valid fenced JSON response
    round3 = f"```json\n{json.dumps(truth_spec.to_dict(), indent=2)}\n```"

    mock = ScriptedMockProvider([round1, round2, round3])
    spec, oracle = synthesize_codec(
        samples,
        name="rpg_save",
        max_rounds=4,
        llm_provider=mock,
        hint="RPG save file with item array",
    )
    assert oracle.passed
    assert spec == truth_spec
    assert len(mock.calls) == 3
    assert "RPG save file with item array" in mock.calls[0][1]
    # Verify oracle feedback was fed into rounds 2 and 3
    assert "Oracle Failures to fix" in mock.calls[1][1]
    assert "Gate 2" in mock.calls[1][1]
    assert "Gate 3" in mock.calls[2][1]


def test_mock_llm_exhaustion_raises_synthesis_error() -> None:
    samples, _ = make_rpg_save_samples()
    bad = CodecSpec(name="bad", fields=[FieldSpec(name="blob", kind="bytes_rest")]).to_dict()
    mock = ScriptedMockProvider([bad, bad])
    with pytest.raises(SynthesisError):
        synthesize_codec(samples, name="rpg_save", max_rounds=2, llm_provider=mock)


def test_extract_json_object_helpers() -> None:
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json_object('Here is the spec:\n{"name": "fmt"}') == {"name": "fmt"}
    with pytest.raises(CodecForgeError):
        extract_json_object("[1, 2, 3]")


def test_gemini_and_openai_http_payload_contracts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def fake_urlopen(req: Any, timeout: float = 60.0) -> _FakeHTTPResponse:
        headers = {k.lower(): v for k, v in req.header_items()}
        body = json.loads(req.data.decode("utf-8"))
        captured.append((req.full_url, headers, body))
        if "interactions" in req.full_url:
            return _FakeHTTPResponse(
                {
                    "steps": [
                        {
                            "type": "model_output",
                            "content": [{"type": "text", "text": '{"ok": true}'}],
                        }
                    ]
                }
            )
        return _FakeHTTPResponse(
            {"choices": [{"message": {"content": '{"ok": true}'}}]}
        )

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        gemini = GeminiInteractionsProvider(api_key="test-gem-key")
        out_g = gemini.generate_json("SYS", "USR")
        assert json.loads(out_g) == {"ok": True}

        openai = OpenAICompatibleProvider(api_key="test-oai-key", provider_name="openai")
        out_o = openai.generate_json("SYS", "USR")
        assert json.loads(out_o) == {"ok": True}

        ollama = OpenAICompatibleProvider(provider_name="ollama")
        out_l = ollama.generate_json("SYS", "USR")
        assert json.loads(out_l) == {"ok": True}

    assert len(captured) == 3
    g_url, g_hdrs, g_body = captured[0]
    assert g_url == "https://generativelanguage.googleapis.com/v1beta/interactions"
    assert g_hdrs["x-goog-api-key"] == "test-gem-key"
    assert g_hdrs["api-revision"] == "2026-05-20"
    assert g_body["model"] == "gemini-4-hydrogen"
    assert g_body["response_format"] == {"type": "text", "mime_type": "application/json"}

    o_url, o_hdrs, o_body = captured[1]
    assert o_url == "https://api.openai.com/v1/chat/completions"
    assert o_hdrs["authorization"] == "Bearer test-oai-key"
    assert o_body["model"] == "gpt-4o-mini"
    assert o_body["response_format"] == {"type": "json_object"}

    l_url, l_hdrs, l_body = captured[2]
    assert l_url == "http://localhost:11434/v1/chat/completions"
    assert l_hdrs["authorization"] == "Bearer ollama"
    assert l_body["model"] == "qwen2.5-coder:7b"

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(CodecForgeError):
        GeminiInteractionsProvider()


def test_heuristic_synthesizes_with_empty_var_str_sample() -> None:
    truth = CodecSpec(
        name="empty_var",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="454D5031"),
            FieldSpec(name="n", kind="scalar", scalar_type="u16le", length_of="s"),
            FieldSpec(name="s", kind="var_str", length_field="n"),
        ],
    )
    samples = [
        encode_obj(truth, {"s": ""}),
        encode_obj(truth, {"s": "hello"}),
        encode_obj(truth, {"s": "world!"}),
    ]
    spec, oracle = synthesize_codec(samples, provider_name="heuristic", name="empty_var")
    assert oracle.passed, oracle.failures
    assert any(f.kind == "var_str" for f in spec.fields)


def test_heuristic_synthesizes_nested_remaining_body_and_inner_var_str() -> None:
    truth = CodecSpec(
        name="nested_len_fmt",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="464D5431"),
            FieldSpec(name="body_len", kind="scalar", scalar_type="u32le", length_of="flags..name"),
            FieldSpec(name="flags", kind="scalar", scalar_type="u16le"),
            FieldSpec(name="name_len", kind="scalar", scalar_type="u16le", length_of="name"),
            FieldSpec(name="name", kind="var_str", length_field="name_len"),
            FieldSpec(name="crc", kind="scalar", scalar_type="u32le", crc32_of="magic..name"),
        ],
    )
    samples = [
        encode_obj(truth, {"flags": 1, "name": "alice_long_username_01"}),
        encode_obj(truth, {"flags": 2, "name": "bob_longer_username_002"}),
        encode_obj(truth, {"flags": 3, "name": "charlie_longest_username_003"}),
    ]
    spec, oracle = synthesize_codec(samples, provider_name="heuristic", name="nested_len_fmt")
    assert oracle.passed, oracle.failures
    assert any(f.kind == "var_str" for f in spec.fields)
    assert sum(1 for f in spec.fields if f.length_of is not None) == 2
    assert spec.fields[-1].crc32_of is not None
