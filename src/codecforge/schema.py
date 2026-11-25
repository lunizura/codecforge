from __future__ import annotations

import codecs
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

from codecforge.errors import SchemaValidationError

ScalarType = Literal[
    "u8", "i8",
    "u16le", "u16be", "i16le", "i16be",
    "u32le", "u32be", "i32le", "i32be",
    "u64le", "u64be", "i64le", "i64be",
    "f32le", "f32be", "f64le", "f64be",
]

FieldKind = Literal[
    "magic",
    "scalar",
    "fixed_bytes",
    "fixed_str",
    "cstr",
    "var_str",
    "var_bytes",
    "bytes_rest",
    "array",
]

VALID_FIELD_KINDS: frozenset[str] = frozenset({
    "magic",
    "scalar",
    "fixed_bytes",
    "fixed_str",
    "cstr",
    "var_str",
    "var_bytes",
    "bytes_rest",
    "array",
})

# scalar_type -> (struct_format, byte_width, is_integer)
SCALAR_STRUCT_FMT: dict[str, tuple[str, int, bool]] = {
    "u8": ("<B", 1, True),    "i8": ("<b", 1, True),
    "u16le": ("<H", 2, True), "u16be": (">H", 2, True),
    "i16le": ("<h", 2, True), "i16be": (">h", 2, True),
    "u32le": ("<I", 4, True), "u32be": (">I", 4, True),
    "i32le": ("<i", 4, True), "i32be": (">i", 4, True),
    "u64le": ("<Q", 8, True), "u64be": (">Q", 8, True),
    "i64le": ("<q", 8, True), "i64be": (">q", 8, True),
    "f32le": ("<f", 4, False), "f32be": (">f", 4, False),
    "f64le": ("<d", 8, False), "f64be": (">d", 8, False),
}

UNSIGNED_MAX: dict[str, int] = {
    "u8": 0xFF,
    "u16le": 0xFFFF, "u16be": 0xFFFF,
    "u32le": 0xFFFFFFFF, "u32be": 0xFFFFFFFF,
    "u64le": 0xFFFFFFFFFFFFFFFF, "u64be": 0xFFFFFFFFFFFFFFFF,
}

SIGNED_BOUNDS: dict[str, tuple[int, int]] = {
    "i8": (-128, 127),
    "i16le": (-32768, 32767), "i16be": (-32768, 32767),
    "i32le": (-2147483648, 2147483647), "i32be": (-2147483648, 2147483647),
    "i64le": (-9223372036854775808, 9223372036854775807),
    "i64be": (-9223372036854775808, 9223372036854775807),
}

IDENT_RE = re.compile(r"^[a-z][a-z0-9_]*$")

RESERVED_KEYWORDS: frozenset[str] = frozenset({
    # Python keywords
    "false", "none", "true", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
    # C++20 keywords & reserved generator symbols
    "alignas", "alignof", "asm", "auto", "bool", "case", "catch", "char",
    "char8_t", "char16_t", "char32_t", "compl", "concept", "const", "consteval",
    "constexpr", "constinit", "const_cast", "co_await", "co_return", "co_yield",
    "decltype", "default", "delete", "do", "double", "dynamic_cast", "enum",
    "explicit", "export", "extern", "float", "friend", "goto", "inline", "int",
    "long", "mutable", "namespace", "new", "noexcept", "nullptr", "operator",
    "private", "protected", "public", "register", "reinterpret_cast", "requires",
    "short", "signed", "sizeof", "static", "static_assert", "static_cast",
    "struct", "switch", "template", "this", "thread_local", "throw", "typedef",
    "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
    "volatile", "wchar_t", "xor", "std", "decode", "encode",
})


def _normalize_hex(raw: Any, field_label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise SchemaValidationError(f"{field_label} must be a non-empty hex string")
    cleaned = raw.strip()
    if len(cleaned) % 2 != 0:
        raise SchemaValidationError(f"{field_label} must have even hex length: {raw!r}")
    try:
        parsed = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SchemaValidationError(f"Invalid hex string for {field_label}: {raw!r}") from exc
    if not parsed:
        raise SchemaValidationError(f"{field_label} must represent at least 1 byte")
    return parsed.hex().upper()


@dataclass
class FieldSpec:
    name: str
    kind: FieldKind
    description: str = ""
    magic_hex: str | None = None
    scalar_type: ScalarType | None = None
    length_of: str | None = None
    count_of: str | None = None
    crc32_of: str | None = None
    size: int | None = None
    encoding: str = "utf-8"
    pad_byte_hex: str = "00"
    length_field: str | None = None
    count_field: str | None = None
    item_fields: list[FieldSpec] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
        }
        if self.description:
            out["description"] = self.description
        if self.magic_hex is not None:
            out["magic_hex"] = self.magic_hex
        if self.scalar_type is not None:
            out["scalar_type"] = self.scalar_type
        if self.length_of is not None:
            out["length_of"] = self.length_of
        if self.count_of is not None:
            out["count_of"] = self.count_of
        if self.crc32_of is not None:
            out["crc32_of"] = self.crc32_of
        if self.size is not None:
            out["size"] = self.size
        if self.kind in ("fixed_str", "cstr", "var_str") or self.encoding != "utf-8":
            out["encoding"] = self.encoding
        if self.kind == "fixed_str" or self.pad_byte_hex != "00":
            out["pad_byte_hex"] = self.pad_byte_hex
        if self.length_field is not None:
            out["length_field"] = self.length_field
        if self.count_field is not None:
            out["count_field"] = self.count_field
        if self.kind == "array" or self.item_fields:
            out["item_fields"] = [item.to_dict() for item in self.item_fields]
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FieldSpec:
        if not isinstance(data, dict):
            raise SchemaValidationError("Field specification must be a mapping")
        if "name" not in data or "kind" not in data:
            raise SchemaValidationError("Field specification requires 'name' and 'kind'")
        name = data["name"]
        kind = data["kind"]
        if not isinstance(name, str) or not isinstance(kind, str):
            raise SchemaValidationError("Field 'name' and 'kind' must be strings")

        magic_hex = data.get("magic_hex")
        if magic_hex is not None:
            magic_hex = _normalize_hex(magic_hex, f"field '{name}' magic_hex")

        pad_raw = data.get("pad_byte_hex", "00")
        if not isinstance(pad_raw, str):
            raise SchemaValidationError(f"field '{name}' pad_byte_hex must be a string")
        pad_byte_hex = _normalize_hex(pad_raw, f"field '{name}' pad_byte_hex") if pad_raw else "00"

        raw_items = data.get("item_fields", [])
        if raw_items is None:
            raw_items = []
        if not isinstance(raw_items, list):
            raise SchemaValidationError(f"field '{name}' item_fields must be a list")

        description = data.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise SchemaValidationError(f"field '{name}' description must be a string")

        encoding = data.get("encoding", "utf-8")
        if not isinstance(encoding, str):
            raise SchemaValidationError(f"field '{name}' encoding must be a string")

        return cls(
            name=name,
            kind=kind,  # type: ignore[arg-type]
            description=description,
            magic_hex=magic_hex,
            scalar_type=data.get("scalar_type"),
            length_of=data.get("length_of"),
            count_of=data.get("count_of"),
            crc32_of=data.get("crc32_of"),
            size=data.get("size"),
            encoding=encoding,
            pad_byte_hex=pad_byte_hex,
            length_field=data.get("length_field"),
            count_field=data.get("count_field"),
            item_fields=[cls.from_dict(item) for item in raw_items],
        )


@dataclass
class CodecSpec:
    name: str
    endian: Literal["le", "be"] = "le"
    description: str = ""
    fields: list[FieldSpec] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "endian": self.endian,
        }
        if self.description:
            out["description"] = self.description
        out["fields"] = [f.to_dict() for f in self.fields]
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodecSpec:
        if not isinstance(data, dict):
            raise SchemaValidationError("CodecSpec root must be a mapping")
        if "name" not in data:
            raise SchemaValidationError("CodecSpec requires 'name'")
        name = data["name"]
        if not isinstance(name, str):
            raise SchemaValidationError("CodecSpec 'name' must be a string")
        endian = data.get("endian", "le")
        if not isinstance(endian, str):
            raise SchemaValidationError("CodecSpec 'endian' must be a string")
        description = data.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise SchemaValidationError("CodecSpec 'description' must be a string")
        raw_fields = data.get("fields", [])
        if not isinstance(raw_fields, list):
            raise SchemaValidationError("CodecSpec 'fields' must be a list")
        return cls(
            name=name,
            endian=endian,  # type: ignore[arg-type]
            description=description,
            fields=[FieldSpec.from_dict(item) for item in raw_fields],
        )

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)

    @classmethod
    def from_yaml(cls, text: str) -> CodecSpec:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SchemaValidationError(f"Invalid YAML in CodecSpec: {exc}") from exc
        if not isinstance(data, dict):
            raise SchemaValidationError("CodecSpec YAML must decode to a mapping")
        return cls.from_dict(data)


def resolve_field_span(fields: list[FieldSpec], expr: str) -> list[str]:
    if not isinstance(expr, str) or not expr.strip():
        raise SchemaValidationError("Field span expression must be a non-empty string")
    names = [f.name for f in fields]
    idx_map = {name: i for i, name in enumerate(names)}
    if ".." in expr:
        parts = expr.split("..")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise SchemaValidationError(f"Invalid field span expression: {expr!r}")
        start_name, end_name = parts
        if start_name not in idx_map:
            raise SchemaValidationError(f"Unknown span start field '{start_name}' in {expr!r}")
        if end_name not in idx_map:
            raise SchemaValidationError(f"Unknown span end field '{end_name}' in {expr!r}")
        i0 = idx_map[start_name]
        i1 = idx_map[end_name]
        if i0 > i1:
            raise SchemaValidationError(
                f"Span start '{start_name}' comes after span end '{end_name}' in {expr!r}"
            )
        return names[i0 : i1 + 1]
    if expr not in idx_map:
        raise SchemaValidationError(f"Unknown field '{expr}' in span expression")
    return [expr]


def _check_identifier(name: str, label: str) -> None:
    if not isinstance(name, str) or not IDENT_RE.match(name):
        raise SchemaValidationError(
            f"{label} '{name}' must match ^[a-z][a-z0-9_]*$"
        )
    if name.lower() in RESERVED_KEYWORDS:
        raise SchemaValidationError(
            f"{label} '{name}' conflicts with a reserved Python/C++20 keyword"
        )


def _validate_field_list(fields: list[FieldSpec], *, allow_bytes_rest: bool) -> None:
    if not fields:
        raise SchemaValidationError("Field list must contain at least one field")

    seen_names: set[str] = set()
    by_name: dict[str, tuple[int, FieldSpec]] = {}

    for idx, f in enumerate(fields):
        _check_identifier(f.name, "Field name")
        if f.name in seen_names:
            raise SchemaValidationError(f"Duplicate field name '{f.name}' in same scope")
        seen_names.add(f.name)
        by_name[f.name] = (idx, f)

        if f.kind not in VALID_FIELD_KINDS:
            raise SchemaValidationError(f"Unknown field kind '{f.kind}' on field '{f.name}'")

    for idx, f in enumerate(fields):
        if f.kind == "bytes_rest":
            if not allow_bytes_rest:
                raise SchemaValidationError("bytes_rest not allowed inside array items")
            if idx != len(fields) - 1:
                raise SchemaValidationError("bytes_rest must be the final field")

        elif f.kind == "magic":
            f.magic_hex = _normalize_hex(f.magic_hex, f"magic field '{f.name}'")

        elif f.kind == "scalar":
            if f.scalar_type not in SCALAR_STRUCT_FMT:
                raise SchemaValidationError(
                    f"Field '{f.name}' has invalid scalar_type '{f.scalar_type}'"
                )
            relations = [x is not None for x in (f.length_of, f.count_of, f.crc32_of)]
            if sum(relations) > 1:
                raise SchemaValidationError(
                    f"Scalar field '{f.name}' may only set one of length_of, count_of, crc32_of"
                )
            if f.length_of is not None:
                if f.scalar_type not in UNSIGNED_MAX:
                    raise SchemaValidationError(
                        f"length_of field '{f.name}' must use an unsigned integer scalar_type"
                    )
                targets = resolve_field_span(fields, f.length_of)
                if f.name in targets:
                    raise SchemaValidationError(
                        f"length_of field '{f.name}' cannot include itself in '{f.length_of}'"
                    )
                for target_name in targets:
                    _, target_f = by_name[target_name]
                    if target_f.crc32_of is not None:
                        raise SchemaValidationError(
                            f"length_of field '{f.name}' cannot cover crc32_of field '{target_name}'"
                        )
            elif f.count_of is not None:
                if f.scalar_type not in UNSIGNED_MAX:
                    raise SchemaValidationError(
                        f"count_of field '{f.name}' must use an unsigned integer scalar_type"
                    )
                if f.count_of not in by_name:
                    raise SchemaValidationError(
                        f"count_of field '{f.name}' references unknown field '{f.count_of}'"
                    )
                target_idx, target_f = by_name[f.count_of]
                if target_idx <= idx:
                    raise SchemaValidationError(
                        f"count_of field '{f.name}' must appear before target array '{f.count_of}'"
                    )
                if target_f.kind != "array" or target_f.count_field != f.name:
                    raise SchemaValidationError(
                        f"count_of target '{f.count_of}' must be an array with count_field='{f.name}'"
                    )
            elif f.crc32_of is not None:
                if f.scalar_type not in ("u32le", "u32be"):
                    raise SchemaValidationError(
                        f"crc32_of field '{f.name}' must use u32le or u32be"
                    )
                targets = resolve_field_span(fields, f.crc32_of)
                if f.name in targets:
                    raise SchemaValidationError(
                        f"crc32_of field '{f.name}' cannot include itself in '{f.crc32_of}'"
                    )

        elif f.kind in ("fixed_bytes", "fixed_str"):
            if not isinstance(f.size, int) or isinstance(f.size, bool) or f.size < 1:
                raise SchemaValidationError(
                    f"Field '{f.name}' ({f.kind}) requires integer size >= 1"
                )
            if f.kind == "fixed_str":
                pad_hex = _normalize_hex(f.pad_byte_hex, f"fixed_str '{f.name}' pad_byte_hex")
                if len(bytes.fromhex(pad_hex)) != 1:
                    raise SchemaValidationError(
                        f"fixed_str '{f.name}' pad_byte_hex must be exactly 1 byte"
                    )
                f.pad_byte_hex = pad_hex
                if f.encoding.lower() not in ("utf-8", "ascii"):
                    raise SchemaValidationError(
                        f"fixed_str '{f.name}' encoding must be 'utf-8' or 'ascii'"
                    )

        elif f.kind in ("cstr", "var_str"):
            try:
                codecs.lookup(f.encoding)
            except LookupError as exc:
                raise SchemaValidationError(
                    f"Field '{f.name}' has unknown encoding '{f.encoding}'"
                ) from exc
            if f.kind == "var_str":
                if not f.length_field or f.length_field not in by_name:
                    raise SchemaValidationError(
                        f"var_str '{f.name}' references unknown length_field '{f.length_field}'"
                    )
                len_idx, len_f = by_name[f.length_field]
                if len_idx >= idx:
                    raise SchemaValidationError(
                        f"var_str '{f.name}' length_field '{f.length_field}' must appear earlier"
                    )
                if len_f.kind != "scalar" or len_f.scalar_type not in UNSIGNED_MAX:
                    raise SchemaValidationError(
                        f"var_str '{f.name}' length_field '{f.length_field}' must be an unsigned integer scalar"
                    )

        elif f.kind == "var_bytes":
            if not f.length_field or f.length_field not in by_name:
                raise SchemaValidationError(
                    f"var_bytes '{f.name}' references unknown length_field '{f.length_field}'"
                )
            len_idx, len_f = by_name[f.length_field]
            if len_idx >= idx:
                raise SchemaValidationError(
                    f"var_bytes '{f.name}' length_field '{f.length_field}' must appear earlier"
                )
            if len_f.kind != "scalar" or len_f.scalar_type not in UNSIGNED_MAX:
                raise SchemaValidationError(
                    f"var_bytes '{f.name}' length_field '{f.length_field}' must be an unsigned integer scalar"
                )

        elif f.kind == "array":
            if not f.count_field or f.count_field not in by_name:
                raise SchemaValidationError(
                    f"array '{f.name}' references unknown count_field '{f.count_field}'"
                )
            cnt_idx, cnt_f = by_name[f.count_field]
            if cnt_idx >= idx:
                raise SchemaValidationError(
                    f"array '{f.name}' count_field '{f.count_field}' must appear earlier"
                )
            if cnt_f.kind != "scalar" or cnt_f.scalar_type not in UNSIGNED_MAX:
                raise SchemaValidationError(
                    f"array '{f.name}' count_field '{f.count_field}' must be an unsigned integer scalar"
                )
            if not f.item_fields:
                raise SchemaValidationError(f"array '{f.name}' must have at least one item_field")
            _validate_field_list(f.item_fields, allow_bytes_rest=False)


def validate_spec(spec: CodecSpec) -> None:
    _check_identifier(spec.name, "CodecSpec name")
    if spec.endian not in ("le", "be"):
        raise SchemaValidationError(f"CodecSpec endian must be 'le' or 'be', got {spec.endian!r}")
    if not spec.fields:
        raise SchemaValidationError("CodecSpec must contain at least one field")
    _validate_field_list(spec.fields, allow_bytes_rest=True)
