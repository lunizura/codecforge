from __future__ import annotations

import copy
import math
import struct
from dataclasses import dataclass
from typing import Any

from codecforge.errors import CodecForgeError, SchemaValidationError
from codecforge.probe import detect_checksums, shannon_entropy
from codecforge.runtime import decode_bytes, encode_obj
from codecforge.schema import (
    SCALAR_STRUCT_FMT,
    SIGNED_BOUNDS,
    UNSIGNED_MAX,
    CodecSpec,
    FieldSpec,
    validate_spec,
)


@dataclass
class OracleResult:
    passed: bool
    gate1_roundtrip_passed: bool
    gate2_coverage_passed: bool
    gate3_mutation_passed: bool
    opaque_byte_ratio: float
    failures: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "gate1_roundtrip_passed": self.gate1_roundtrip_passed,
            "gate2_coverage_passed": self.gate2_coverage_passed,
            "gate3_mutation_passed": self.gate3_mutation_passed,
            "opaque_byte_ratio": round(self.opaque_byte_ratio, 4),
            "failures": list(self.failures),
        }


def _default_item_for_fields(fields: list[FieldSpec]) -> dict[str, Any]:
    item: dict[str, Any] = {}
    for f in fields:
        if f.kind == "magic":
            continue
        if f.kind == "scalar":
            if f.length_of or f.count_of or f.crc32_of:
                continue
            assert f.scalar_type is not None
            if f.scalar_type in UNSIGNED_MAX or f.scalar_type in SIGNED_BOUNDS:
                item[f.name] = 1
            else:
                item[f.name] = 1.25
        elif f.kind == "fixed_bytes":
            assert f.size is not None
            item[f.name] = b"\x01" * f.size
        elif f.kind == "fixed_str":
            assert f.size is not None
            pad_val = bytes.fromhex(f.pad_byte_hex)[0]
            item[f.name] = "a" if ord("a") != pad_val else "b"
        elif f.kind in ("cstr", "var_str"):
            item[f.name] = "cf_item"
        elif f.kind in ("var_bytes", "bytes_rest"):
            item[f.name] = b"\x01\x02"
        elif f.kind == "array":
            item[f.name] = [_default_item_for_fields(f.item_fields)]
    return item


def _mutate_fields(
    fields: list[FieldSpec],
    target_dict: dict[str, Any],
    fallback_dicts: list[dict[str, Any]] | None = None,
) -> None:
    field_by_name = {f.name: f for f in fields}
    for f in fields:
        if f.kind == "magic":
            continue
        if f.kind == "scalar":
            if f.length_of or f.count_of or f.crc32_of:
                continue
            assert f.scalar_type is not None
            if f.scalar_type in UNSIGNED_MAX:
                target_dict[f.name] = (int(target_dict[f.name]) + 1) % (
                    UNSIGNED_MAX[f.scalar_type] + 1
                )
            elif f.scalar_type in SIGNED_BOUNDS:
                lo, hi = SIGNED_BOUNDS[f.scalar_type]
                v = int(target_dict[f.name])
                target_dict[f.name] = v + 1 if v < hi else lo
            else:
                fmt = SCALAR_STRUCT_FMT[f.scalar_type][0]
                new_f = float(target_dict[f.name]) + 1.25
                target_dict[f.name] = struct.unpack(fmt, struct.pack(fmt, new_f))[0]
        elif f.kind == "var_str":
            target_dict[f.name] = str(target_dict[f.name]) + "_cf"
        elif f.kind == "cstr":
            target_dict[f.name] = str(target_dict[f.name]) + "_z"
        elif f.kind == "fixed_str":
            assert f.size is not None
            s = str(target_dict[f.name])
            pad_val = bytes.fromhex(f.pad_byte_hex)[0]
            raw = s.encode(f.encoding)
            if len(raw) < f.size:
                append_ch = next(c for c in ("X", "Y", "Z") if ord(c) != pad_val)
                target_dict[f.name] = s + append_ch
            else:
                replacement = next(
                    c for c in ("Z", "A", "B") if ord(c) != pad_val and not s.startswith(c)
                )
                candidate = replacement + s[1:]
                if len(candidate.encode(f.encoding)) <= f.size:
                    target_dict[f.name] = candidate
                else:
                    target_dict[f.name] = replacement
        elif f.kind in ("var_bytes", "bytes_rest"):
            target_dict[f.name] = bytes(target_dict[f.name]) + b"\xab\xcd"
        elif f.kind == "fixed_bytes":
            b = bytes(target_dict[f.name])
            target_dict[f.name] = bytes([b[0] ^ 0xFF]) + b[1:]
        elif f.kind == "array":
            arr = target_dict[f.name]
            if isinstance(arr, list):
                assert f.count_field is not None
                cnt_scalar = field_by_name[f.count_field].scalar_type
                assert cnt_scalar is not None
                max_cnt = UNSIGNED_MAX[cnt_scalar]
                exemplar: dict[str, Any] | None = None
                if len(arr) > 0:
                    exemplar = arr[0]
                elif fallback_dicts:
                    for fb in fallback_dicts:
                        fb_arr = fb.get(f.name)
                        if isinstance(fb_arr, list) and len(fb_arr) > 0:
                            exemplar = fb_arr[0]
                            break
                if exemplar is None:
                    exemplar = _default_item_for_fields(f.item_fields)
                if len(arr) + 2 <= max_cnt:
                    cloned1 = copy.deepcopy(exemplar)
                    _mutate_fields(f.item_fields, cloned1)
                    cloned2 = copy.deepcopy(cloned1)
                    _mutate_fields(f.item_fields, cloned2)
                    arr.append(cloned1)
                    arr.append(cloned2)
                elif len(arr) + 1 <= max_cnt:
                    cloned1 = copy.deepcopy(exemplar)
                    _mutate_fields(f.item_fields, cloned1)
                    arr.append(cloned1)
                elif len(arr) > 0:
                    arr.pop()


def _compare_non_derived(
    fields: list[FieldSpec],
    expected: dict[str, Any],
    actual: dict[str, Any],
    failures: list[str],
    prefix: str = "",
) -> None:
    for f in fields:
        full_name = f"{prefix}{f.name}"
        if f.kind == "magic":
            continue
        if f.kind == "scalar" and (f.length_of or f.count_of or f.crc32_of):
            continue
        if f.name not in actual:
            failures.append(f"Gate 3: missing mutated field '{full_name}' after re-decode")
            continue
        exp_val = expected[f.name]
        act_val = actual[f.name]
        if f.kind == "scalar" and f.scalar_type in ("f32le", "f32be", "f64le", "f64be"):
            if not math.isclose(float(exp_val), float(act_val), rel_tol=1e-5, abs_tol=1e-5):
                failures.append(
                    f"Gate 3: float field '{full_name}' mismatch ({act_val!r} != {exp_val!r})"
                )
        elif f.kind == "array":
            if not isinstance(act_val, list) or len(act_val) != len(exp_val):
                failures.append(
                    f"Gate 3: array '{full_name}' count mismatch "
                    f"({len(act_val) if isinstance(act_val, list) else type(act_val).__name__} "
                    f"!= {len(exp_val)})"
                )
                continue
            for idx, (e_item, a_item) in enumerate(zip(exp_val, act_val)):
                _compare_non_derived(
                    f.item_fields,
                    e_item,
                    a_item,
                    failures,
                    prefix=f"{full_name}[{idx}].",
                )
        else:
            if act_val != exp_val:
                failures.append(
                    f"Gate 3: field '{full_name}' reverted or mismatched "
                    f"({act_val!r} != {exp_val!r})"
                )


def verify_codec(
    spec: CodecSpec,
    samples: list[bytes],
    max_opaque_ratio: float = 0.50,
) -> OracleResult:
    try:
        validate_spec(spec)
    except SchemaValidationError as exc:
        return OracleResult(
            passed=False,
            gate1_roundtrip_passed=False,
            gate2_coverage_passed=False,
            gate3_mutation_passed=False,
            opaque_byte_ratio=1.0,
            failures=[f"SchemaValidationError: {exc}"],
        )

    if not samples:
        return OracleResult(
            passed=False,
            gate1_roundtrip_passed=False,
            gate2_coverage_passed=False,
            gate3_mutation_passed=False,
            opaque_byte_ratio=1.0,
            failures=["No samples provided to verify_codec"],
        )

    failures: list[str] = []

    # Gate 1: Bit-Exact Sample Round-Trip
    gate1_ok = True
    first_spans: list[tuple[str, int, int]] | None = None
    first_sample_ok = False
    decoded_samples: list[dict[str, Any]] = []

    for idx, sample in enumerate(samples):
        try:
            decoded, spans = decode_bytes(spec, sample)
            reencoded = encode_obj(spec, decoded)
        except CodecForgeError as exc:
            gate1_ok = False
            failures.append(f"Gate 1 sample[{idx}] failed: {exc}")
            continue

        if reencoded != sample:
            gate1_ok = False
            m = next(
                (
                    i
                    for i in range(min(len(sample), len(reencoded)))
                    if sample[i] != reencoded[i]
                ),
                min(len(sample), len(reencoded)),
            )
            failures.append(
                f"Gate 1 sample[{idx}] byte mismatch at 0x{m:x} "
                f"(len {len(sample)} vs {len(reencoded)}): "
                f"expected {sample[max(0, m - 8) : m + 8].hex()} "
                f"got {reencoded[max(0, m - 8) : m + 8].hex()}"
            )
            continue

        decoded_samples.append(decoded)
        if idx == 0:
            first_spans = spans
            first_sample_ok = True

    # Gate 2: Anti-Passthrough & Structure Coverage Guard
    gate2_ok = False
    opaque_ratio = 1.0
    if first_sample_ok and first_spans is not None:
        gate2_ok = True
        s0 = samples[0]
        overall_ent = shannon_entropy(s0)
        field_by_name = {f.name: f for f in spec.fields}
        low_ent_opaque_bytes = 0
        for name, start, end in first_spans:
            f = field_by_name[name]
            if f.kind in ("bytes_rest", "fixed_bytes", "var_bytes"):
                if shannon_entropy(s0[start:end]) < 7.0:
                    low_ent_opaque_bytes += end - start
        opaque_ratio = low_ent_opaque_bytes / max(1, len(s0))

        if overall_ent < 7.0:
            if len(spec.fields) == 1 and spec.fields[0].kind in (
                "bytes_rest",
                "fixed_bytes",
            ):
                gate2_ok = False
                failures.append("Gate 2: Single-field opaque passthrough schema is forbidden")
            if opaque_ratio > max_opaque_ratio:
                gate2_ok = False
                failures.append(
                    f"Gate 2: Opaque low-entropy byte ratio {opaque_ratio:.2f} "
                    f"exceeds limit {max_opaque_ratio:.2f}"
                )
            if (
                len(samples) >= 2
                and len(s0) >= 2
                and all(len(s) >= 2 and s[:2] == s0[:2] for s in samples)
                and all(0x20 <= b <= 0x7E for b in s0[:2])
                and spec.fields[0].kind != "magic"
            ):
                gate2_ok = False
                failures.append(
                    "Gate 2: Samples share a printable ASCII header prefix at offset 0, "
                    "so fields[0] must be kind='magic'"
                )

    # Gate 3: Semantic Mutation Fuzzing
    gate3_ok = False
    if first_sample_ok:
        gate3_failures: list[str] = []
        crc_cands = detect_checksums(samples)
        if crc_cands and not any(f.crc32_of is not None for f in spec.fields):
            gate3_failures.append(
                f"Gate 3: samples have deterministic trailer CRC32 ({crc_cands[0].scalar_type}), "
                f"but spec has no field with crc32_of"
            )

        try:
            base_obj = decoded_samples[0]
            mut = copy.deepcopy(base_obj)
            _mutate_fields(spec.fields, mut, fallback_dicts=decoded_samples[1:])
            mut_bytes = encode_obj(spec, mut)
            re_obj, _ = decode_bytes(spec, mut_bytes)
            re_bytes = encode_obj(spec, re_obj)
            if re_bytes != mut_bytes:
                gate3_failures.append(
                    "Gate 3: mutated re-encode bytes differ from initial mutated encode"
                )
            _compare_non_derived(spec.fields, mut, re_obj, gate3_failures)
        except CodecForgeError as exc:
            gate3_failures.append(f"Gate 3 mutation round-trip failed: {exc}")

        if not gate3_failures:
            gate3_ok = True
        else:
            failures.extend(gate3_failures)

    passed = gate1_ok and gate2_ok and gate3_ok
    return OracleResult(
        passed=passed,
        gate1_roundtrip_passed=gate1_ok,
        gate2_coverage_passed=gate2_ok,
        gate3_mutation_passed=gate3_ok,
        opaque_byte_ratio=opaque_ratio,
        failures=failures,
    )
