from __future__ import annotations

from codecforge.schema import (
    SCALAR_STRUCT_FMT,
    UNSIGNED_MAX,
    CodecSpec,
    FieldSpec,
    resolve_field_span,
    validate_spec,
)

_CPP_SCALAR_TYPE: dict[str, str] = {
    "u8": "std::uint8_t",
    "i8": "std::int8_t",
    "u16le": "std::uint16_t",
    "u16be": "std::uint16_t",
    "i16le": "std::int16_t",
    "i16be": "std::int16_t",
    "u32le": "std::uint32_t",
    "u32be": "std::uint32_t",
    "i32le": "std::int32_t",
    "i32be": "std::int32_t",
    "u64le": "std::uint64_t",
    "u64be": "std::uint64_t",
    "i64le": "std::int64_t",
    "i64be": "std::int64_t",
    "f32le": "float",
    "f32be": "float",
    "f64le": "double",
    "f64be": "double",
}


def _to_pascal(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_") if part)


def _cpp_prelude() -> str:
    return """#pragma once

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace codecforge_gen {

inline void _cf_require(bool cond, const char* msg) {
    if (!cond) {
        throw std::runtime_error(msg);
    }
}

inline void _cf_check_utf8(const std::string& s, const char* field_name) {
    std::size_t i = 0;
    const std::size_t n = s.size();
    while (i < n) {
        const auto b0 = static_cast<std::uint8_t>(s[i]);
        if (b0 <= 0x7Fu) {
            ++i;
        } else if ((b0 & 0xE0u) == 0xC0u) {
            if (i + 1 >= n || b0 < 0xC2u) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            const auto b1 = static_cast<std::uint8_t>(s[i + 1]);
            if ((b1 & 0xC0u) != 0x80u) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            i += 2;
        } else if ((b0 & 0xF0u) == 0xE0u) {
            if (i + 2 >= n) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            const auto b1 = static_cast<std::uint8_t>(s[i + 1]);
            const auto b2 = static_cast<std::uint8_t>(s[i + 2]);
            if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            if ((b0 == 0xE0u && b1 < 0xA0u) || (b0 == 0xEDu && b1 >= 0xA0u)) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            i += 3;
        } else if ((b0 & 0xF8u) == 0xF0u) {
            if (i + 3 >= n || b0 > 0xF4u) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            const auto b1 = static_cast<std::uint8_t>(s[i + 1]);
            const auto b2 = static_cast<std::uint8_t>(s[i + 2]);
            const auto b3 = static_cast<std::uint8_t>(s[i + 3]);
            if ((b1 & 0xC0u) != 0x80u || (b2 & 0xC0u) != 0x80u || (b3 & 0xC0u) != 0x80u) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            if ((b0 == 0xF0u && b1 < 0x90u) || (b0 == 0xF4u && b1 > 0x8Fu)) {
                throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
            }
            i += 4;
        } else {
            throw std::runtime_error(std::string("Invalid UTF-8 in ") + field_name);
        }
    }
}

inline std::uint32_t crc32_ieee(std::span<const std::uint8_t> buf) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::uint8_t byte : buf) {
        crc ^= static_cast<std::uint32_t>(byte);
        for (int k = 0; k < 8; ++k) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

inline std::uint8_t read_u8(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 1 <= buf.size(), "Truncated u8");
    return buf[pos++];
}

inline std::int8_t read_i8(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint8_t u = read_u8(buf, pos);
    std::int8_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::uint16_t read_u16le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 2 <= buf.size(), "Truncated u16le");
    const std::uint16_t v = static_cast<std::uint16_t>(buf[pos]) |
                            (static_cast<std::uint16_t>(buf[pos + 1]) << 8);
    pos += 2;
    return v;
}

inline std::uint16_t read_u16be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 2 <= buf.size(), "Truncated u16be");
    const std::uint16_t v = (static_cast<std::uint16_t>(buf[pos]) << 8) |
                            static_cast<std::uint16_t>(buf[pos + 1]);
    pos += 2;
    return v;
}

inline std::int16_t read_i16le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint16_t u = read_u16le(buf, pos);
    std::int16_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::int16_t read_i16be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint16_t u = read_u16be(buf, pos);
    std::int16_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::uint32_t read_u32le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 4 <= buf.size(), "Truncated u32le");
    const std::uint32_t v = static_cast<std::uint32_t>(buf[pos]) |
                            (static_cast<std::uint32_t>(buf[pos + 1]) << 8) |
                            (static_cast<std::uint32_t>(buf[pos + 2]) << 16) |
                            (static_cast<std::uint32_t>(buf[pos + 3]) << 24);
    pos += 4;
    return v;
}

inline std::uint32_t read_u32be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 4 <= buf.size(), "Truncated u32be");
    const std::uint32_t v = (static_cast<std::uint32_t>(buf[pos]) << 24) |
                            (static_cast<std::uint32_t>(buf[pos + 1]) << 16) |
                            (static_cast<std::uint32_t>(buf[pos + 2]) << 8) |
                            static_cast<std::uint32_t>(buf[pos + 3]);
    pos += 4;
    return v;
}

inline std::int32_t read_i32le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint32_t u = read_u32le(buf, pos);
    std::int32_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::int32_t read_i32be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint32_t u = read_u32be(buf, pos);
    std::int32_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::uint64_t read_u64le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 8 <= buf.size(), "Truncated u64le");
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(buf[pos + static_cast<std::size_t>(i)]) << (8 * i);
    }
    pos += 8;
    return v;
}

inline std::uint64_t read_u64be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    _cf_require(pos + 8 <= buf.size(), "Truncated u64be");
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint64_t>(buf[pos + static_cast<std::size_t>(i)]);
    }
    pos += 8;
    return v;
}

inline std::int64_t read_i64le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint64_t u = read_u64le(buf, pos);
    std::int64_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline std::int64_t read_i64be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint64_t u = read_u64be(buf, pos);
    std::int64_t v = 0;
    std::memcpy(&v, &u, sizeof(v));
    return v;
}

inline float read_f32le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint32_t u = read_u32le(buf, pos);
    float v = 0.0f;
    std::memcpy(&v, &u, sizeof(v));
    _cf_require(!std::isnan(v), "NaN float encountered");
    return v;
}

inline float read_f32be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint32_t u = read_u32be(buf, pos);
    float v = 0.0f;
    std::memcpy(&v, &u, sizeof(v));
    _cf_require(!std::isnan(v), "NaN float encountered");
    return v;
}

inline double read_f64le(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint64_t u = read_u64le(buf, pos);
    double v = 0.0;
    std::memcpy(&v, &u, sizeof(v));
    _cf_require(!std::isnan(v), "NaN double encountered");
    return v;
}

inline double read_f64be(std::span<const std::uint8_t> buf, std::size_t& pos) {
    const std::uint64_t u = read_u64be(buf, pos);
    double v = 0.0;
    std::memcpy(&v, &u, sizeof(v));
    _cf_require(!std::isnan(v), "NaN double encountered");
    return v;
}

inline void write_u8(std::vector<std::uint8_t>& out, std::uint8_t v) {
    out.push_back(v);
}

inline void write_i8(std::vector<std::uint8_t>& out, std::int8_t v) {
    std::uint8_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    out.push_back(u);
}

inline void write_u16le(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
}

inline void write_u16be(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

inline void write_i16le(std::vector<std::uint8_t>& out, std::int16_t v) {
    std::uint16_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u16le(out, u);
}

inline void write_i16be(std::vector<std::uint8_t>& out, std::int16_t v) {
    std::uint16_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u16be(out, u);
}

inline void write_u32le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
}

inline void write_u32be(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
}

inline void write_i32le(std::vector<std::uint8_t>& out, std::int32_t v) {
    std::uint32_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u32le(out, u);
}

inline void write_i32be(std::vector<std::uint8_t>& out, std::int32_t v) {
    std::uint32_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u32be(out, u);
}

inline void write_u64le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

inline void write_u64be(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

inline void write_i64le(std::vector<std::uint8_t>& out, std::int64_t v) {
    std::uint64_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u64le(out, u);
}

inline void write_i64be(std::vector<std::uint8_t>& out, std::int64_t v) {
    std::uint64_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u64be(out, u);
}

inline void write_f32le(std::vector<std::uint8_t>& out, float v) {
    _cf_require(std::isfinite(v), "Non-finite float");
    std::uint32_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u32le(out, u);
}

inline void write_f32be(std::vector<std::uint8_t>& out, float v) {
    _cf_require(std::isfinite(v), "Non-finite float");
    std::uint32_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u32be(out, u);
}

inline void write_f64le(std::vector<std::uint8_t>& out, double v) {
    _cf_require(std::isfinite(v), "Non-finite double");
    std::uint64_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u64le(out, u);
}

inline void write_f64be(std::vector<std::uint8_t>& out, double v) {
    _cf_require(std::isfinite(v), "Non-finite double");
    std::uint64_t u = 0;
    std::memcpy(&u, &v, sizeof(u));
    write_u64be(out, u);
}
"""


def _emit_struct(
    struct_name: str,
    fields: list[FieldSpec],
    *,
    is_root: bool,
    out_blocks: list[str],
) -> None:
    item_struct_names: dict[str, str] = {}
    for f in fields:
        if f.kind == "array":
            child_name = f"{struct_name}{_to_pascal(f.name)}Item"
            item_struct_names[f.name] = child_name
            _emit_struct(child_name, f.item_fields, is_root=False, out_blocks=out_blocks)

    lines: list[str] = [f"struct {struct_name} {{"]

    # Members
    for f in fields:
        if f.kind == "magic":
            continue
        elif f.kind == "scalar":
            assert f.scalar_type is not None
            lines.append(f"    {_CPP_SCALAR_TYPE[f.scalar_type]} {f.name}{{}};")
        elif f.kind in ("fixed_bytes", "var_bytes", "bytes_rest"):
            lines.append(f"    std::vector<std::uint8_t> {f.name};")
        elif f.kind in ("fixed_str", "cstr", "var_str"):
            lines.append(f"    std::string {f.name};")
        elif f.kind == "array":
            lines.append(f"    std::vector<{item_struct_names[f.name]}> {f.name};")

    lines.append("")
    lines.append(f"    bool operator==(const {struct_name}&) const = default;")
    lines.append("")

    # Decode method
    if is_root:
        lines.append(
            f"    static {struct_name} decode(std::span<const std::uint8_t> _cf_buf) {{"
        )
        lines.append("        std::size_t _cf_pos = 0;")
    else:
        lines.append(
            f"    static {struct_name} decode_item("
            "std::span<const std::uint8_t> _cf_buf, std::size_t& _cf_pos) {"
        )

    lines.append(f"        {struct_name} _cf_obj{{}};")
    for f in fields:
        lines.append(f"        const std::size_t _cf_start_{f.name} = _cf_pos;")
        if f.kind == "magic":
            raw_bytes = bytes.fromhex(f.magic_hex or "")
            hex_list = ", ".join(f"0x{b:02X}u" for b in raw_bytes)
            lines.append(
                f"        static constexpr std::array<std::uint8_t, {len(raw_bytes)}> "
                f"_cf_magic_{f.name}{{{hex_list}}};"
            )
            lines.append(
                f'        _cf_require(_cf_pos + {len(raw_bytes)} <= _cf_buf.size(), "Truncated magic {f.name}");'
            )
            lines.append(
                f"        for (std::size_t _cf_i = 0; _cf_i < {len(raw_bytes)}; ++_cf_i) {{"
            )
            lines.append(
                f'            _cf_require(_cf_buf[_cf_pos + _cf_i] == _cf_magic_{f.name}[_cf_i], "Magic mismatch on {f.name}");'
            )
            lines.append("        }")
            lines.append(f"        _cf_pos += {len(raw_bytes)};")
        elif f.kind == "scalar":
            assert f.scalar_type is not None
            lines.append(f"        _cf_obj.{f.name} = read_{f.scalar_type}(_cf_buf, _cf_pos);")
        elif f.kind == "fixed_bytes":
            assert f.size is not None
            lines.append(
                f'        _cf_require(_cf_pos + {f.size} <= _cf_buf.size(), "Truncated fixed_bytes {f.name}");'
            )
            lines.append(
                f"        _cf_obj.{f.name}.assign(_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_pos), "
                f"_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_pos + {f.size}));"
            )
            lines.append(f"        _cf_pos += {f.size};")
        elif f.kind == "fixed_str":
            assert f.size is not None
            pad_byte = bytes.fromhex(f.pad_byte_hex)[0]
            lines.append(
                f'        _cf_require(_cf_pos + {f.size} <= _cf_buf.size(), "Truncated fixed_str {f.name}");'
            )
            lines.append(f"        std::size_t _cf_pad_{f.name} = {f.size};")
            lines.append(
                f"        for (std::size_t _cf_i = 0; _cf_i < {f.size}; ++_cf_i) {{"
            )
            lines.append(
                f"            if (_cf_buf[_cf_pos + _cf_i] == 0x{pad_byte:02X}u) {{"
            )
            lines.append(f"                _cf_pad_{f.name} = _cf_i;")
            lines.append("                break;")
            lines.append("            }")
            lines.append("        }")
            lines.append(
                f"        for (std::size_t _cf_i = _cf_pad_{f.name}; _cf_i < {f.size}; ++_cf_i) {{"
            )
            lines.append(
                f'            _cf_require(_cf_buf[_cf_pos + _cf_i] == 0x{pad_byte:02X}u, "Non-canonical padding in {f.name}");'
            )
            lines.append("        }")
            lines.append(
                f"        _cf_obj.{f.name}.assign(reinterpret_cast<const char*>(_cf_buf.data() + _cf_pos), "
                f"_cf_pad_{f.name});"
            )
            lines.append(f'        _cf_check_utf8(_cf_obj.{f.name}, "{f.name}");')
            lines.append(f"        _cf_pos += {f.size};")
        elif f.kind == "cstr":
            lines.append(f"        std::size_t _cf_nul_{f.name} = _cf_pos;")
            lines.append(
                f"        while (_cf_nul_{f.name} < _cf_buf.size() && _cf_buf[_cf_nul_{f.name}] != 0u) {{"
            )
            lines.append(f"            ++_cf_nul_{f.name};")
            lines.append("        }")
            lines.append(
                f'        _cf_require(_cf_nul_{f.name} < _cf_buf.size(), "Unterminated cstr {f.name}");'
            )
            lines.append(
                f"        _cf_obj.{f.name}.assign(reinterpret_cast<const char*>(_cf_buf.data() + _cf_pos), "
                f"_cf_nul_{f.name} - _cf_pos);"
            )
            lines.append(f'        _cf_check_utf8(_cf_obj.{f.name}, "{f.name}");')
            lines.append(f"        _cf_pos = _cf_nul_{f.name} + 1;")
        elif f.kind == "var_str":
            assert f.length_field is not None
            lines.append(
                f"        const std::size_t _cf_len_{f.name} = static_cast<std::size_t>(_cf_obj.{f.length_field});"
            )
            lines.append(
                f'        _cf_require(_cf_pos + _cf_len_{f.name} <= _cf_buf.size(), "Truncated var_str {f.name}");'
            )
            lines.append(
                f"        _cf_obj.{f.name}.assign(reinterpret_cast<const char*>(_cf_buf.data() + _cf_pos), "
                f"_cf_len_{f.name});"
            )
            lines.append(f'        _cf_check_utf8(_cf_obj.{f.name}, "{f.name}");')
            lines.append(f"        _cf_pos += _cf_len_{f.name};")
        elif f.kind == "var_bytes":
            assert f.length_field is not None
            lines.append(
                f"        const std::size_t _cf_len_{f.name} = static_cast<std::size_t>(_cf_obj.{f.length_field});"
            )
            lines.append(
                f'        _cf_require(_cf_pos + _cf_len_{f.name} <= _cf_buf.size(), "Truncated var_bytes {f.name}");'
            )
            lines.append(
                f"        _cf_obj.{f.name}.assign(_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_pos), "
                f"_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_pos + _cf_len_{f.name}));"
            )
            lines.append(f"        _cf_pos += _cf_len_{f.name};")
        elif f.kind == "bytes_rest":
            lines.append(
                f"        _cf_obj.{f.name}.assign(_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_pos), _cf_buf.end());"
            )
            lines.append("        _cf_pos = _cf_buf.size();")
        elif f.kind == "array":
            assert f.count_field is not None
            child = item_struct_names[f.name]
            lines.append(
                f"        const std::size_t _cf_cnt_{f.name} = static_cast<std::size_t>(_cf_obj.{f.count_field});"
            )
            lines.append(f"        _cf_obj.{f.name}.reserve(_cf_cnt_{f.name});")
            lines.append(
                f"        for (std::size_t _cf_i = 0; _cf_i < _cf_cnt_{f.name}; ++_cf_i) {{"
            )
            lines.append(
                f"            _cf_obj.{f.name}.push_back({child}::decode_item(_cf_buf, _cf_pos));"
            )
            lines.append("        }")
        lines.append(f"        const std::size_t _cf_end_{f.name} = _cf_pos;")

    # Post-list CRC32 checks
    for f in fields:
        if f.kind == "scalar" and f.crc32_of is not None:
            targets = resolve_field_span(fields, f.crc32_of)
            lines.append(f"        std::vector<std::uint8_t> _cf_cov_{f.name};")
            for t in targets:
                lines.append(
                    f"        _cf_cov_{f.name}.insert(_cf_cov_{f.name}.end(), "
                    f"_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_start_{t}), "
                    f"_cf_buf.begin() + static_cast<std::ptrdiff_t>(_cf_end_{t}));"
                )
            lines.append(
                f"        const std::uint32_t _cf_expected_{f.name} = crc32_ieee(_cf_cov_{f.name});"
            )
            lines.append(
                f'        _cf_require(static_cast<std::uint32_t>(_cf_obj.{f.name}) == _cf_expected_{f.name}, '
                f'"CRC32 mismatch on {f.name}");'
            )

    if is_root:
        lines.append('        _cf_require(_cf_pos == _cf_buf.size(), "Unconsumed trailing bytes");')

    lines.append("        return _cf_obj;")
    lines.append("    }")
    lines.append("")

    # Encode method
    enc_name = "encode" if is_root else "encode_item"
    lines.append(
        f"    static std::vector<std::uint8_t> {enc_name}(const {struct_name}& _cf_obj) {{"
    )
    for f in fields:
        lines.append(f"        std::vector<std::uint8_t> _cf_chunk_{f.name};")

    # Pass 1
    for f in fields:
        if f.kind == "magic":
            raw_bytes = bytes.fromhex(f.magic_hex or "")
            hex_list = ", ".join(f"0x{b:02X}u" for b in raw_bytes)
            lines.append(f"        _cf_chunk_{f.name} = {{{hex_list}}};")
        elif f.kind == "scalar":
            assert f.scalar_type is not None
            if f.count_of is not None:
                max_v = UNSIGNED_MAX[f.scalar_type]
                lines.append(
                    f'        _cf_require(_cf_obj.{f.count_of}.size() <= {max_v}ULL, '
                    f'"Array {f.count_of} exceeds {f.scalar_type} max");'
                )
                lines.append(
                    f"        write_{f.scalar_type}(_cf_chunk_{f.name}, "
                    f"static_cast<{_CPP_SCALAR_TYPE[f.scalar_type]}>(_cf_obj.{f.count_of}.size()));"
                )
            elif f.length_of is None and f.crc32_of is None:
                lines.append(f"        write_{f.scalar_type}(_cf_chunk_{f.name}, _cf_obj.{f.name});")
        elif f.kind == "fixed_bytes":
            assert f.size is not None
            lines.append(
                f'        _cf_require(_cf_obj.{f.name}.size() == {f.size}, "fixed_bytes {f.name} size mismatch");'
            )
            lines.append(f"        _cf_chunk_{f.name} = _cf_obj.{f.name};")
        elif f.kind == "fixed_str":
            assert f.size is not None
            pad_byte = bytes.fromhex(f.pad_byte_hex)[0]
            lines.append(
                f'        _cf_require(_cf_obj.{f.name}.size() <= {f.size}, "fixed_str {f.name} exceeds size");'
            )
            lines.append(f"        for (char _cf_ch : _cf_obj.{f.name}) {{")
            lines.append(
                f'            _cf_require(static_cast<std::uint8_t>(_cf_ch) != 0x{pad_byte:02X}u, '
                f'"fixed_str {f.name} contains pad byte");'
            )
            lines.append("        }")
            lines.append(
                f"        _cf_chunk_{f.name}.assign({f.size}, static_cast<std::uint8_t>(0x{pad_byte:02X}u));"
            )
            lines.append(
                f"        for (std::size_t _cf_i = 0; _cf_i < _cf_obj.{f.name}.size(); ++_cf_i) {{"
            )
            lines.append(
                f"            _cf_chunk_{f.name}[_cf_i] = static_cast<std::uint8_t>(_cf_obj.{f.name}[_cf_i]);"
            )
            lines.append("        }")
        elif f.kind == "cstr":
            lines.append(f"        for (char _cf_ch : _cf_obj.{f.name}) {{")
            lines.append(
                f'            _cf_require(_cf_ch != \'\\0\', "cstr {f.name} contains embedded NUL");'
            )
            lines.append("        }")
            lines.append(
                f"        _cf_chunk_{f.name}.assign(_cf_obj.{f.name}.begin(), _cf_obj.{f.name}.end());"
            )
            lines.append(f"        _cf_chunk_{f.name}.push_back(0u);")
        elif f.kind == "var_str":
            lines.append(
                f"        _cf_chunk_{f.name}.assign(_cf_obj.{f.name}.begin(), _cf_obj.{f.name}.end());"
            )
        elif f.kind in ("var_bytes", "bytes_rest"):
            lines.append(f"        _cf_chunk_{f.name} = _cf_obj.{f.name};")
        elif f.kind == "array":
            child = item_struct_names[f.name]
            lines.append(f"        for (const auto& _cf_item : _cf_obj.{f.name}) {{")
            lines.append(f"            const auto _cf_ib = {child}::encode_item(_cf_item);")
            lines.append(
                f"            _cf_chunk_{f.name}.insert(_cf_chunk_{f.name}.end(), _cf_ib.begin(), _cf_ib.end());"
            )
            lines.append("        }")

    # Pass 2: pre-size length_of then backpatch in reverse order
    for f in fields:
        if f.kind == "scalar" and f.length_of is not None:
            assert f.scalar_type is not None
            width = SCALAR_STRUCT_FMT[f.scalar_type][1]
            lines.append(f"        _cf_chunk_{f.name}.assign({width}, 0u);")

    for f in reversed(fields):
        if f.kind == "scalar" and f.length_of is not None:
            assert f.scalar_type is not None
            targets = resolve_field_span(fields, f.length_of)
            sum_expr = " + ".join(f"_cf_chunk_{t}.size()" for t in targets)
            max_v = UNSIGNED_MAX[f.scalar_type]
            lines.append(f"        const std::size_t _cf_len_{f.name} = {sum_expr};")
            lines.append(
                f'        _cf_require(_cf_len_{f.name} <= {max_v}ULL, '
                f'"length_of {f.name} exceeds {f.scalar_type} max");'
            )
            lines.append(f"        _cf_chunk_{f.name}.clear();")
            lines.append(
                f"        write_{f.scalar_type}(_cf_chunk_{f.name}, "
                f"static_cast<{_CPP_SCALAR_TYPE[f.scalar_type]}>(_cf_len_{f.name}));"
            )

    # Pass 3: crc32_of
    for f in fields:
        if f.kind == "scalar" and f.crc32_of is not None:
            assert f.scalar_type is not None
            targets = resolve_field_span(fields, f.crc32_of)
            lines.append(f"        std::vector<std::uint8_t> _cf_cov_{f.name};")
            for t in targets:
                lines.append(
                    f"        _cf_cov_{f.name}.insert(_cf_cov_{f.name}.end(), "
                    f"_cf_chunk_{t}.begin(), _cf_chunk_{t}.end());"
                )
            lines.append(
                f"        const std::uint32_t _cf_crc_{f.name} = crc32_ieee(_cf_cov_{f.name});"
            )
            lines.append(
                f"        write_{f.scalar_type}(_cf_chunk_{f.name}, _cf_crc_{f.name});"
            )

    lines.append("        std::vector<std::uint8_t> _cf_out;")
    for f in fields:
        lines.append(
            f"        _cf_out.insert(_cf_out.end(), _cf_chunk_{f.name}.begin(), _cf_chunk_{f.name}.end());"
        )
    lines.append("        return _cf_out;")
    lines.append("    }")
    lines.append("};")
    out_blocks.append("\n".join(lines))


def generate_cpp_header(spec: CodecSpec) -> str:
    validate_spec(spec)
    struct_name = _to_pascal(spec.name)
    blocks: list[str] = []
    _emit_struct(struct_name, spec.fields, is_root=True, out_blocks=blocks)
    return _cpp_prelude() + "\n" + "\n\n".join(blocks) + "\n\n}  // namespace codecforge_gen\n"
