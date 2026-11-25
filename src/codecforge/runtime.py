from __future__ import annotations

import math
import struct
import zlib
from typing import Any

from codecforge.errors import CodecDecodeError, CodecEncodeError
from codecforge.schema import (
    SCALAR_STRUCT_FMT,
    SIGNED_BOUNDS,
    UNSIGNED_MAX,
    CodecSpec,
    FieldSpec,
    resolve_field_span,
    validate_spec,
)


def _decode_field_list(
    fields: list[FieldSpec],
    data: bytes,
    pos: int,
) -> tuple[dict[str, Any], int, list[tuple[str, int, int]]]:
    out: dict[str, Any] = {}
    spans: list[tuple[str, int, int]] = []

    for f in fields:
        start = pos

        if f.kind == "magic":
            expected = bytes.fromhex(f.magic_hex or "")
            end = pos + len(expected)
            if end > len(data):
                raise CodecDecodeError(
                    f"Truncated magic '{f.name}' at 0x{pos:x}: need {len(expected)} bytes"
                )
            if data[pos:end] != expected:
                raise CodecDecodeError(
                    f"Magic mismatch on '{f.name}' at 0x{pos:x}: "
                    f"expected {expected.hex().upper()}, got {data[pos:end].hex().upper()}"
                )
            out[f.name] = expected.hex().upper()
            pos = end

        elif f.kind == "scalar":
            assert f.scalar_type is not None
            fmt, width, is_integer = SCALAR_STRUCT_FMT[f.scalar_type]
            if pos + width > len(data):
                raise CodecDecodeError(
                    f"Truncated scalar '{f.name}' ({f.scalar_type}) at 0x{pos:x}: need {width} bytes"
                )
            val = struct.unpack_from(fmt, data, pos)[0]
            if not is_integer and math.isnan(val):
                raise CodecDecodeError(f"NaN float encountered in '{f.name}' at 0x{pos:x}")
            out[f.name] = val
            pos += width

        elif f.kind == "fixed_bytes":
            assert f.size is not None
            end = pos + f.size
            if end > len(data):
                raise CodecDecodeError(
                    f"Truncated fixed_bytes '{f.name}' at 0x{pos:x}: need {f.size} bytes"
                )
            out[f.name] = data[pos:end]
            pos = end

        elif f.kind == "fixed_str":
            assert f.size is not None
            end = pos + f.size
            if end > len(data):
                raise CodecDecodeError(
                    f"Truncated fixed_str '{f.name}' at 0x{pos:x}: need {f.size} bytes"
                )
            raw = data[pos:end]
            pad = bytes.fromhex(f.pad_byte_hex)
            idx = raw.find(pad)
            if idx != -1 and any(b != pad[0] for b in raw[idx:]):
                raise CodecDecodeError(
                    f"Non-canonical bytes after pad byte in fixed_str '{f.name}' at 0x{pos:x}"
                )
            content = raw[:idx] if idx != -1 else raw
            try:
                out[f.name] = content.decode(f.encoding, errors="strict")
            except UnicodeDecodeError as exc:
                raise CodecDecodeError(
                    f"Invalid {f.encoding} in fixed_str '{f.name}' at 0x{pos:x}: {exc}"
                ) from exc
            pos = end

        elif f.kind == "cstr":
            nul = data.find(b"\x00", pos)
            if nul == -1:
                raise CodecDecodeError(f"Unterminated cstr '{f.name}' starting at 0x{pos:x}")
            try:
                out[f.name] = data[pos:nul].decode(f.encoding, errors="strict")
            except UnicodeDecodeError as exc:
                raise CodecDecodeError(
                    f"Invalid {f.encoding} in cstr '{f.name}' at 0x{pos:x}: {exc}"
                ) from exc
            pos = nul + 1

        elif f.kind in ("var_str", "var_bytes"):
            assert f.length_field is not None
            n = int(out[f.length_field])
            if n < 0 or pos + n > len(data):
                raise CodecDecodeError(
                    f"Truncated {f.kind} '{f.name}': need {n} bytes at 0x{pos:x}"
                )
            raw = data[pos : pos + n]
            if f.kind == "var_str":
                try:
                    out[f.name] = raw.decode(f.encoding, errors="strict")
                except UnicodeDecodeError as exc:
                    raise CodecDecodeError(
                        f"Invalid {f.encoding} in var_str '{f.name}' at 0x{pos:x}: {exc}"
                    ) from exc
            else:
                out[f.name] = raw
            pos += n

        elif f.kind == "array":
            assert f.count_field is not None
            cnt = int(out[f.count_field])
            items: list[dict[str, Any]] = []
            for _ in range(cnt):
                item_dict, pos, _ = _decode_field_list(f.item_fields, data, pos)
                items.append(item_dict)
            out[f.name] = items

        elif f.kind == "bytes_rest":
            out[f.name] = data[pos:]
            pos = len(data)

        else:
            raise CodecDecodeError(f"Unsupported field kind '{f.kind}'")

        spans.append((f.name, start, pos))

    span_map = {name: (s, e) for name, s, e in spans}
    for f in fields:
        if f.kind == "scalar" and f.crc32_of is not None:
            targets = resolve_field_span(fields, f.crc32_of)
            covered = b"".join(data[span_map[t][0] : span_map[t][1]] for t in targets)
            expected_crc = zlib.crc32(covered) & 0xFFFFFFFF
            if out[f.name] != expected_crc:
                raise CodecDecodeError(
                    f"CRC32 mismatch on '{f.name}': got 0x{out[f.name]:08x}, "
                    f"expected 0x{expected_crc:08x}"
                )

    return out, pos, spans


def decode_bytes(
    spec: CodecSpec, data: bytes
) -> tuple[dict[str, Any], list[tuple[str, int, int]]]:
    validate_spec(spec)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CodecDecodeError("Input data must be bytes-like")
    buf = bytes(data)
    out, end_pos, spans = _decode_field_list(spec.fields, buf, 0)
    if end_pos != len(buf):
        raise CodecDecodeError(f"Unconsumed trailing bytes: {len(buf) - end_pos}")
    return out, spans


def _pack_scalar(f: FieldSpec, val: Any) -> bytes:
    assert f.scalar_type is not None
    fmt, _, is_integer = SCALAR_STRUCT_FMT[f.scalar_type]
    if is_integer:
        if isinstance(val, bool) or not isinstance(val, int):
            raise CodecEncodeError(
                f"Scalar '{f.name}' ({f.scalar_type}) requires int, got {type(val).__name__}"
            )
        if f.scalar_type in UNSIGNED_MAX:
            max_v = UNSIGNED_MAX[f.scalar_type]
            if val < 0 or val > max_v:
                raise CodecEncodeError(
                    f"Scalar '{f.name}' ({f.scalar_type}) value {val} out of range [0, {max_v}]"
                )
        else:
            lo, hi = SIGNED_BOUNDS[f.scalar_type]
            if val < lo or val > hi:
                raise CodecEncodeError(
                    f"Scalar '{f.name}' ({f.scalar_type}) value {val} out of range [{lo}, {hi}]"
                )
    else:
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise CodecEncodeError(
                f"Scalar '{f.name}' ({f.scalar_type}) requires float/int, got {type(val).__name__}"
            )
        if not math.isfinite(float(val)):
            raise CodecEncodeError(f"Scalar '{f.name}' ({f.scalar_type}) must be finite")
        val = float(val)
    try:
        return struct.pack(fmt, val)
    except struct.error as exc:
        raise CodecEncodeError(f"Failed packing scalar '{f.name}': {exc}") from exc


def _encode_field_list(fields: list[FieldSpec], obj: dict[str, Any]) -> bytes:
    if not isinstance(obj, dict):
        raise CodecEncodeError("Object to encode must be a dictionary")

    chunks: dict[str, bytes] = {}

    # Pass 1: Leaf content, magic, count_of, and plain scalars
    for f in fields:
        if f.kind == "magic":
            chunks[f.name] = bytes.fromhex(f.magic_hex or "")

        elif f.kind == "scalar":
            assert f.scalar_type is not None
            if f.count_of is not None:
                items = obj.get(f.count_of)
                if not isinstance(items, list):
                    raise CodecEncodeError(
                        f"count_of target '{f.count_of}' for '{f.name}' must be a list"
                    )
                max_c = UNSIGNED_MAX[f.scalar_type]
                if len(items) > max_c:
                    raise CodecEncodeError(
                        f"Array '{f.count_of}' length {len(items)} exceeds {f.scalar_type} max"
                    )
                chunks[f.name] = _pack_scalar(f, len(items))
            elif f.length_of is not None or f.crc32_of is not None:
                chunks[f.name] = b""
            else:
                if f.name not in obj:
                    raise CodecEncodeError(f"Missing required scalar field '{f.name}'")
                chunks[f.name] = _pack_scalar(f, obj[f.name])

        elif f.kind == "fixed_bytes":
            assert f.size is not None
            if f.name not in obj or not isinstance(obj[f.name], (bytes, bytearray)):
                raise CodecEncodeError(f"Field '{f.name}' (fixed_bytes) must be bytes/bytearray")
            b = bytes(obj[f.name])
            if len(b) != f.size:
                raise CodecEncodeError(
                    f"Field '{f.name}' (fixed_bytes) expected {f.size} bytes, got {len(b)}"
                )
            chunks[f.name] = b

        elif f.kind == "fixed_str":
            assert f.size is not None
            if f.name not in obj or not isinstance(obj[f.name], str):
                raise CodecEncodeError(f"Field '{f.name}' (fixed_str) must be str")
            try:
                raw = obj[f.name].encode(f.encoding)
            except UnicodeEncodeError as exc:
                raise CodecEncodeError(f"Failed encoding fixed_str '{f.name}': {exc}") from exc
            pad = bytes.fromhex(f.pad_byte_hex)
            if pad in raw:
                raise CodecEncodeError(
                    f"fixed_str '{f.name}' cannot contain pad byte 0x{f.pad_byte_hex}"
                )
            if len(raw) > f.size:
                raise CodecEncodeError(
                    f"fixed_str '{f.name}' encoded length {len(raw)} exceeds size {f.size}"
                )
            chunks[f.name] = raw.ljust(f.size, pad)

        elif f.kind == "cstr":
            if f.name not in obj or not isinstance(obj[f.name], str):
                raise CodecEncodeError(f"Field '{f.name}' (cstr) must be str")
            try:
                raw = obj[f.name].encode(f.encoding)
            except UnicodeEncodeError as exc:
                raise CodecEncodeError(f"Failed encoding cstr '{f.name}': {exc}") from exc
            if b"\x00" in raw:
                raise CodecEncodeError(f"cstr '{f.name}' cannot contain embedded NUL byte")
            chunks[f.name] = raw + b"\x00"

        elif f.kind == "var_str":
            if f.name not in obj or not isinstance(obj[f.name], str):
                raise CodecEncodeError(f"Field '{f.name}' (var_str) must be str")
            try:
                chunks[f.name] = obj[f.name].encode(f.encoding)
            except UnicodeEncodeError as exc:
                raise CodecEncodeError(f"Failed encoding var_str '{f.name}': {exc}") from exc

        elif f.kind in ("var_bytes", "bytes_rest"):
            if f.name not in obj or not isinstance(obj[f.name], (bytes, bytearray)):
                raise CodecEncodeError(f"Field '{f.name}' ({f.kind}) must be bytes/bytearray")
            chunks[f.name] = bytes(obj[f.name])

        elif f.kind == "array":
            if f.name not in obj or not isinstance(obj[f.name], list):
                raise CodecEncodeError(f"Field '{f.name}' (array) must be a list")
            chunks[f.name] = b"".join(
                _encode_field_list(f.item_fields, item) for item in obj[f.name]
            )

        else:
            raise CodecEncodeError(f"Unsupported field kind '{f.kind}'")

    # Pass 2: length_of backpatch (pre-size all length_of widths, then reverse order)
    for f in fields:
        if f.kind == "scalar" and f.length_of is not None:
            assert f.scalar_type is not None
            width = SCALAR_STRUCT_FMT[f.scalar_type][1]
            chunks[f.name] = b"\x00" * width

    for f in reversed(fields):
        if f.kind == "scalar" and f.length_of is not None:
            assert f.scalar_type is not None
            targets = resolve_field_span(fields, f.length_of)
            total_len = sum(len(chunks[t]) for t in targets)
            max_len = UNSIGNED_MAX[f.scalar_type]
            if total_len < 0 or total_len > max_len:
                raise CodecEncodeError(
                    f"length_of '{f.name}' value {total_len} exceeds {f.scalar_type} max"
                )
            chunks[f.name] = _pack_scalar(f, total_len)

    # Pass 3: crc32_of backpatch
    for f in fields:
        if f.kind == "scalar" and f.crc32_of is not None:
            targets = resolve_field_span(fields, f.crc32_of)
            covered = b"".join(chunks[t] for t in targets)
            crc = zlib.crc32(covered) & 0xFFFFFFFF
            chunks[f.name] = _pack_scalar(f, crc)

    return b"".join(chunks[f.name] for f in fields)


def encode_obj(spec: CodecSpec, obj: dict[str, Any]) -> bytes:
    validate_spec(spec)
    return _encode_field_list(spec.fields, obj)
