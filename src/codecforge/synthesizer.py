from __future__ import annotations

import json
import math
import struct
from typing import Literal

from codecforge.errors import CodecForgeError, SynthesisError
from codecforge.llm_client import (
    LLMProvider,
    build_llm_provider,
    extract_json_object,
)
from codecforge.oracle import OracleResult, verify_codec
from codecforge.probe import (
    LengthRelationCandidate,
    align_samples,
    detect_checksums,
    detect_lengths,
    probe_samples,
)
from codecforge.schema import CodecSpec, FieldSpec, ScalarType, validate_spec


def _is_printable_utf8(raw: bytes) -> bool:
    if not raw:
        return True
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ch in "\t\r\n" for ch in text)


def _is_canonical_nul_padded_ascii(chunks: list[bytes]) -> bool:
    saw_pad = False
    for raw in chunks:
        idx = raw.find(b"\x00")
        if idx == 0:
            return False
        if idx != -1:
            if any(b != 0 for b in raw[idx:]):
                return False
            saw_pad = True
            prefix = raw[:idx]
        else:
            prefix = raw
        if not all(0x20 <= b <= 0x7E for b in prefix):
            return False
    return saw_pad


def _looks_like_f32(chunks: list[bytes], endian: Literal["le", "be"]) -> bool:
    f_fmt = "<f" if endian == "le" else ">f"
    u_fmt = "<I" if endian == "le" else ">I"
    has_fraction = False
    for raw in chunks:
        fv = struct.unpack(f_fmt, raw)[0]
        iv = struct.unpack(u_fmt, raw)[0]
        if not math.isfinite(fv):
            return False
        if not (1e-3 <= abs(fv) <= 1e6):
            return False
        if iv <= 0xFFFF:
            return False
        if fv != int(fv):
            has_fraction = True
        elif abs(fv) >= 1e5:
            return False
    return has_fraction


def _emit_fixed_block(
    work: list[bytes],
    sample_starts: list[int],
    block_size: int,
    endian: Literal["le", "be"],
    rem_body_map: dict[int, LengthRelationCandidate],
    fields: list[FieldSpec],
    counter_start: int,
) -> int:
    counter = counter_start
    off = 0
    s0_base = sample_starts[0]
    while off < block_size:
        abs_s0 = s0_base + off
        if abs_s0 in rem_body_map:
            rc = rem_body_map[abs_s0]
            fields.append(
                FieldSpec(
                    name=f"len_{counter}",
                    kind="scalar",
                    scalar_type=rc.scalar_type,
                    length_of="__PENDING_REM_BODY__",
                )
            )
            counter += 1
            off += rc.width
            continue

        rem = block_size - off
        if rem >= 4:
            str_chunks = [w[sample_starts[k] + off : sample_starts[k] + off + rem] for k, w in enumerate(work)]
            if _is_canonical_nul_padded_ascii(str_chunks):
                fields.append(
                    FieldSpec(
                        name=f"str_{counter}",
                        kind="fixed_str",
                        size=rem,
                        encoding="utf-8",
                        pad_byte_hex="00",
                    )
                )
                counter += 1
                off += rem
                continue

        if rem >= 4:
            chunks4 = [w[sample_starts[k] + off : sample_starts[k] + off + 4] for k, w in enumerate(work)]
            st: ScalarType
            if _looks_like_f32(chunks4, endian):
                st = "f32le" if endian == "le" else "f32be"
            else:
                st = "u32le" if endian == "le" else "u32be"
            fields.append(FieldSpec(name=f"field_{counter}", kind="scalar", scalar_type=st))
            counter += 1
            off += 4
        elif rem >= 2:
            st = "u16le" if endian == "le" else "u16be"
            fields.append(FieldSpec(name=f"field_{counter}", kind="scalar", scalar_type=st))
            counter += 1
            off += 2
        else:
            fields.append(FieldSpec(name=f"field_{counter}", kind="scalar", scalar_type="u8"))
            counter += 1
            off += 1
    return counter


def synthesize_heuristic(
    samples: list[bytes],
    name: str = "synthesized_format",
) -> CodecSpec:
    if len(samples) < 2:
        raise SynthesisError("synthesize_heuristic requires at least 2 samples")

    crc_cands = detect_checksums(samples)
    trailer_crc = crc_cands[0] if crc_cands else None
    strip_n = 4 if trailer_crc else 0
    work = [s[: len(s) - strip_n] if strip_n else s for s in samples]

    segments = align_samples(samples, strip_trailer_bytes=strip_n)
    len_cands = detect_lengths(samples, segments, strip_trailer_bytes=strip_n)

    be_votes = sum(
        1 for c in [*crc_cands, *len_cands] if c.scalar_type.endswith("be")
    )
    le_votes = sum(
        1 for c in [*crc_cands, *len_cands] if c.scalar_type.endswith("le")
    )
    endian: Literal["le", "be"] = "be" if be_votes > le_votes else "le"

    seg_len_map = {
        c.target_segment_index: c
        for c in len_cands
        if c.target_kind == "segment_index" and c.target_segment_index is not None
    }
    rem_body_map = {
        c.sample0_offset: c
        for c in len_cands
        if c.target_kind == "remaining_body"
    }

    fields: list[FieldSpec] = []
    counter = 0
    pending_seg_len_fields: dict[int, FieldSpec] = {}

    for idx, seg in enumerate(segments):
        if seg.kind == "const":
            assert seg.const_bytes_hex is not None
            fields.append(
                FieldSpec(
                    name=f"magic_{counter}",
                    kind="magic",
                    magic_hex=seg.const_bytes_hex,
                )
            )
            counter += 1

        elif seg.kind == "fixed_var":
            assert seg.fixed_size is not None
            reserved_cand = seg_len_map.get(idx + 1)
            reserved_tail = reserved_cand.width if reserved_cand is not None else 0
            prefix_size = seg.fixed_size - reserved_tail
            if prefix_size < 0:
                raise SynthesisError(
                    f"Length candidate width {reserved_tail} exceeds fixed_var segment {idx} size"
                )
            if prefix_size > 0:
                counter = _emit_fixed_block(
                    work,
                    [s for s, _ in seg.sample_slices],
                    prefix_size,
                    endian,
                    rem_body_map,
                    fields,
                    counter,
                )
            if reserved_cand is not None:
                len_f = FieldSpec(
                    name=f"len_{counter}",
                    kind="scalar",
                    scalar_type=reserved_cand.scalar_type,
                    length_of="__PENDING_SEG__",
                )
                fields.append(len_f)
                pending_seg_len_fields[idx + 1] = len_f
                counter += 1

        elif seg.kind == "shifted_var":
            if idx in seg_len_map:
                cand = seg_len_map[idx]
                s0_seg_start = seg.sample_slices[0][0]
                if cand.sample0_offset >= s0_seg_start:
                    # Embedded fixed prefix + length field + variable tail within this segment
                    rel = cand.sample0_offset - s0_seg_start
                    if rel > 0:
                        counter = _emit_fixed_block(
                            work,
                            [s for s, _ in seg.sample_slices],
                            rel,
                            endian,
                            rem_body_map,
                            fields,
                            counter,
                        )
                    len_f = FieldSpec(
                        name=f"len_{counter}",
                        kind="scalar",
                        scalar_type=cand.scalar_type,
                        length_of="__PENDING_SEG__",
                    )
                    fields.append(len_f)
                    counter += 1
                    payload_off = rel + cand.width
                    chunks = [
                        work[k][s + payload_off : e]
                        for k, (s, e) in enumerate(seg.sample_slices)
                    ]
                else:
                    len_f = pending_seg_len_fields[idx]
                    chunks = [
                        work[k][s:e] for k, (s, e) in enumerate(seg.sample_slices)
                    ]

                if all(_is_printable_utf8(c) for c in chunks):
                    payload_name = f"text_{counter}"
                    fields.append(
                        FieldSpec(
                            name=payload_name,
                            kind="var_str",
                            length_field=len_f.name,
                        )
                    )
                else:
                    payload_name = f"bytes_{counter}"
                    fields.append(
                        FieldSpec(
                            name=payload_name,
                            kind="var_bytes",
                            length_field=len_f.name,
                        )
                    )
                len_f.length_of = payload_name
                counter += 1
            else:
                chunks = [work[k][s:e] for k, (s, e) in enumerate(seg.sample_slices)]
                if all(
                    len(c) >= 1 and c[-1:] == b"\x00" and b"\x00" not in c[:-1] and _is_printable_utf8(c[:-1])
                    for c in chunks
                ):
                    fields.append(FieldSpec(name=f"cstr_{counter}", kind="cstr"))
                    counter += 1
                elif idx == len(segments) - 1 and strip_n == 0:
                    fields.append(FieldSpec(name=f"tail_{counter}", kind="bytes_rest"))
                    counter += 1
                else:
                    raise SynthesisError(
                        f"Cannot heuristically infer shifted_var segment {idx} without length/cstr structure"
                    )

    if not fields:
        raise SynthesisError("Heuristic synthesis produced no fields")

    for i, f in enumerate(fields):
        if f.length_of == "__PENDING_REM_BODY__":
            if i + 1 >= len(fields):
                raise SynthesisError(f"Remaining-body length field '{f.name}' has no following fields")
            if i + 1 == len(fields) - 1:
                f.length_of = fields[i + 1].name
            else:
                f.length_of = f"{fields[i + 1].name}..{fields[-1].name}"

    if trailer_crc is not None:
        span_expr = fields[0].name if len(fields) == 1 else f"{fields[0].name}..{fields[-1].name}"
        fields.append(
            FieldSpec(
                name="checksum",
                kind="scalar",
                scalar_type=trailer_crc.scalar_type,
                crc32_of=span_expr,
            )
        )

    spec = CodecSpec(
        name=name,
        endian=endian,
        description="Synthesized binary format specification",
        fields=fields,
    )
    validate_spec(spec)
    return spec


SYSTEM_PROMPT = """You are an expert binary format reverse-engineering synthesizer.
Given multi-sample alignment, entropy, length-prefix, and CRC32 probe evidence, output a single JSON object conforming strictly to CodecSpec:
{
  "name": "<snake_case_identifier>",
  "endian": "le" | "be",
  "description": "<short summary>",
  "fields": [ FieldSpec, ... ]
}

FieldSpec kinds:
- "magic": {"name": "...", "kind": "magic", "magic_hex": "UPPER_HEX"}
- "scalar": {"name": "...", "kind": "scalar", "scalar_type": "u8|i8|u16le|u16be|i16le|i16be|u32le|u32be|i32le|i32be|u64le|u64be|i64le|i64be|f32le|f32be|f64le|f64be", optional "length_of": "field_or_start..end", optional "count_of": "array_field", optional "crc32_of": "field_or_start..end"}
- "fixed_bytes": {"name": "...", "kind": "fixed_bytes", "size": <int>}
- "fixed_str": {"name": "...", "kind": "fixed_str", "size": <int>, "encoding": "utf-8", "pad_byte_hex": "00"}
- "cstr": {"name": "...", "kind": "cstr", "encoding": "utf-8"}
- "var_str": {"name": "...", "kind": "var_str", "length_field": "<earlier_uint_scalar>", "encoding": "utf-8"}
- "var_bytes": {"name": "...", "kind": "var_bytes", "length_field": "<earlier_uint_scalar>"}
- "bytes_rest": {"name": "...", "kind": "bytes_rest"} (only allowed as last top-level field, avoid opaque blobs)
- "array": {"name": "...", "kind": "array", "count_field": "<earlier_uint_scalar>", "item_fields": [ FieldSpec, ... ]}

Rules:
1. All identifiers must match ^[a-z][a-z0-9_]*$ and avoid Python/C++ keywords (e.g., avoid 'std', 'class', 'encode', 'decode').
2. Never collapse structured headers or variable regions into a single bytes_rest blob.
3. Every length prefix must set length_of, every array count must set count_of, and every CRC32 trailer must set crc32_of.
4. Output JSON ONLY with no markdown prose."""


def synthesize_with_llm(
    samples: list[bytes],
    provider: LLMProvider,
    name: str = "synthesized_format",
    max_rounds: int = 4,
) -> tuple[CodecSpec, OracleResult]:
    if len(samples) < 2:
        raise SynthesisError("synthesize_with_llm requires at least 2 samples")

    report = probe_samples(samples)
    summary = report.to_prompt_summary(samples)

    last_failures: list[str] = []
    last_attempt_json: str | None = None

    for round_idx in range(1, max_rounds + 1):
        prompt_parts = [
            f"Target format name: {name}",
            "",
            summary,
        ]
        if round_idx > 1:
            prompt_parts.extend([
                "",
                f"Previous attempt (round {round_idx - 1}) failed verification:",
                last_attempt_json or "<invalid JSON / schema>",
                "",
                "Oracle Failures to fix:",
                *[f"- {err}" for err in last_failures],
                "",
                "Return a corrected complete CodecSpec JSON object.",
            ])
        user_prompt = "\n".join(prompt_parts)
        raw = provider.generate_json(SYSTEM_PROMPT, user_prompt)
        try:
            data = extract_json_object(raw)
            spec = CodecSpec.from_dict(data)
            last_attempt_json = json.dumps(spec.to_dict(), indent=2)
            oracle = verify_codec(spec, samples)
        except CodecForgeError as exc:
            last_attempt_json = raw[:1500]
            last_failures = [str(exc)]
            continue

        if oracle.passed:
            return spec, oracle
        last_failures = list(oracle.failures)

    raise SynthesisError(
        f"LLM synthesis failed after {max_rounds} rounds: {'; '.join(last_failures)}"
    )


def synthesize_codec(
    samples: list[bytes],
    provider_name: str = "heuristic",
    name: str = "synthesized_format",
    model: str | None = None,
    max_rounds: int = 4,
    llm_provider: LLMProvider | None = None,
) -> tuple[CodecSpec, OracleResult]:
    if llm_provider is not None:
        return synthesize_with_llm(samples, llm_provider, name=name, max_rounds=max_rounds)
    if provider_name == "heuristic":
        spec = synthesize_heuristic(samples, name=name)
        oracle = verify_codec(spec, samples)
        if not oracle.passed:
            raise SynthesisError(
                f"Heuristic spec failed 3-Gate Oracle: {'; '.join(oracle.failures)}"
            )
        return spec, oracle
    provider = build_llm_provider(provider_name, model=model)
    return synthesize_with_llm(samples, provider, name=name, max_rounds=max_rounds)
