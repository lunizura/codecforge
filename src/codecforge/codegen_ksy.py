from __future__ import annotations

from typing import Any

import yaml

from codecforge.schema import CodecSpec, FieldSpec, validate_spec

_KSY_SCALAR_MAP: dict[str, str] = {
    "u8": "u1",
    "i8": "s1",
    "u16le": "u2le",
    "u16be": "u2be",
    "i16le": "s2le",
    "i16be": "s2be",
    "u32le": "u4le",
    "u32be": "u4be",
    "i32le": "s4le",
    "i32be": "s4be",
    "u64le": "u8le",
    "u64be": "u8be",
    "i64le": "s8le",
    "i64be": "s8be",
    "f32le": "f4le",
    "f32be": "f4be",
    "f64le": "f8le",
    "f64be": "f8be",
}


def _ksy_encoding(enc: str) -> str:
    low = enc.lower()
    if low in ("utf-8", "utf8"):
        return "UTF-8"
    if low == "ascii":
        return "ASCII"
    return enc


def _build_seq_and_types(
    fields: list[FieldSpec],
    types_out: dict[str, Any],
    prefix: str = "",
) -> list[dict[str, Any]]:
    seq: list[dict[str, Any]] = []
    for f in fields:
        entry: dict[str, Any] = {"id": f.name}
        if f.kind == "magic":
            entry["contents"] = list(bytes.fromhex(f.magic_hex or ""))
        elif f.kind == "scalar":
            assert f.scalar_type is not None
            entry["type"] = _KSY_SCALAR_MAP[f.scalar_type]
        elif f.kind == "fixed_bytes":
            entry["size"] = f.size
        elif f.kind == "fixed_str":
            entry["type"] = "str"
            entry["size"] = f.size
            entry["pad-right"] = bytes.fromhex(f.pad_byte_hex)[0]
            entry["encoding"] = _ksy_encoding(f.encoding)
        elif f.kind == "cstr":
            entry["type"] = "strz"
            entry["encoding"] = _ksy_encoding(f.encoding)
        elif f.kind == "var_str":
            entry["type"] = "str"
            entry["size"] = f.length_field
            entry["encoding"] = _ksy_encoding(f.encoding)
        elif f.kind == "var_bytes":
            entry["size"] = f.length_field
        elif f.kind == "bytes_rest":
            entry["size-eos"] = True
        elif f.kind == "array":
            base_type_name = f"{prefix}{f.name}_item"
            item_type_name = base_type_name
            suffix_idx = 2
            while item_type_name in types_out:
                item_type_name = f"{base_type_name}_{suffix_idx}"
                suffix_idx += 1
            entry["type"] = item_type_name
            entry["repeat"] = "expr"
            entry["repeat-expr"] = f.count_field
            types_out[item_type_name] = {
                "seq": _build_seq_and_types(
                    f.item_fields, types_out, prefix=f"{prefix}{f.name}_"
                )
            }
        if f.description:
            entry["doc"] = f.description
        seq.append(entry)
    return seq


def generate_kaitai_ksy(spec: CodecSpec) -> str:
    validate_spec(spec)
    meta: dict[str, Any] = {
        "id": spec.name,
        "endian": spec.endian,
    }
    if spec.description:
        meta["doc"] = spec.description

    types_out: dict[str, Any] = {}
    seq = _build_seq_and_types(spec.fields, types_out)

    ksy: dict[str, Any] = {
        "meta": meta,
        "seq": seq,
    }
    if types_out:
        ksy["types"] = types_out

    return yaml.safe_dump(ksy, sort_keys=False, allow_unicode=True)
