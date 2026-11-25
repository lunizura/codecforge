from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from codecforge.codegen_cpp import generate_cpp_header
from codecforge.codegen_ksy import generate_kaitai_ksy
from codecforge.codegen_py import generate_python_module
from codecforge.report_html import generate_html_report
from codecforge.schema import CodecSpec, FieldSpec
from tests.fixtures import (
    make_corrupt_samples,
    make_fixed_header_samples,
    make_net_packet_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


def _find_cpp20_compiler() -> tuple[str, str] | None:
    for name in ("g++", "clang++"):
        exe = shutil.which(name)
        if not exe:
            continue
        proc = subprocess.run(
            [exe, "-std=c++20", "-x", "c++", "-", "-fsyntax-only"],
            input=b"#include <span>\nint main() { return 0; }\n",
            capture_output=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return ("gnu", exe)

    if os.name == "nt":
        candidates = [
            Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"),
            Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"),
            Path(r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"),
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"),
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"),
        ]
        for vcvars in candidates:
            if vcvars.is_file():
                return ("msvc", str(vcvars))
    return None


@pytest.mark.parametrize(
    "builder",
    [
        make_rpg_save_samples,
        make_simple_save_samples,
        make_net_packet_samples,
        make_fixed_header_samples,
    ],
)
def test_generated_python_module_roundtrip_and_mutation(builder) -> None:
    samples, spec = builder()
    src = generate_python_module(spec)
    assert "import codecforge" not in src

    ns: dict[str, Any] = {}
    exec(compile(src, f"<{spec.name}_py>", "exec"), ns)

    for raw in samples:
        obj = ns["decode"](raw)
        repacked = ns["encode"](obj)
        assert repacked == raw

    # Mutate first sample and verify re-decode matches
    mut = ns["decode"](samples[0])
    if "player_name" in mut:
        mut["player_name"] = "MutatedHeroName"
        mut["items"].append({"item_id": 555, "qty": 9})
    elif "bio" in mut:
        mut["bio"] = "UpdatedBioString"
    elif "tag" in mut:
        mut["tag"] = "updated_tag"
        mut["payload"] = b"\x01\x02\x03\x04\x05"
    elif "label" in mut:
        mut["label"] = "edited"
    mut_bytes = ns["encode"](mut)
    mut_re = ns["decode"](mut_bytes)
    assert ns["encode"](mut_re) == mut_bytes


def test_generated_python_f32_overflow_raises_value_error() -> None:
    spec = CodecSpec(
        name="float_only",
        fields=[FieldSpec(name="x", kind="scalar", scalar_type="f32le")],
    )
    ns: dict[str, Any] = {}
    exec(compile(generate_python_module(spec), "<float_only>", "exec"), ns)
    with pytest.raises(ValueError):
        ns["encode"]({"x": 1e100})
    with pytest.raises(ValueError):
        ns["encode"]({})
    with pytest.raises(ValueError):
        ns["encode"]("not_a_dict")


def test_generated_kaitai_ksy_valid_yaml() -> None:
    _, spec = make_rpg_save_samples()
    ksy_text = generate_kaitai_ksy(spec)
    parsed = yaml.safe_load(ksy_text)
    assert parsed["meta"]["id"] == "rpg_save"
    assert parsed["meta"]["endian"] == "le"
    assert len(parsed["seq"]) == len(spec.fields)
    assert "items_item" in parsed["types"]
    assert parsed["seq"][6]["id"] == "item_count"
    assert parsed["seq"][7]["repeat"] == "expr"


def test_generated_kaitai_ksy_nested_array_no_type_collision() -> None:
    nested_spec = CodecSpec(
        name="nested_ksy",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="4E455354"),
            FieldSpec(name="cnt", kind="scalar", scalar_type="u8", count_of="groups"),
            FieldSpec(
                name="groups",
                kind="array",
                count_field="cnt",
                item_fields=[
                    FieldSpec(name="inner_cnt", kind="scalar", scalar_type="u8", count_of="items"),
                    FieldSpec(
                        name="items",
                        kind="array",
                        count_field="inner_cnt",
                        item_fields=[FieldSpec(name="val", kind="scalar", scalar_type="u16le")],
                    ),
                ],
            ),
            FieldSpec(name="item_cnt2", kind="scalar", scalar_type="u8", count_of="items"),
            FieldSpec(
                name="items",
                kind="array",
                count_field="item_cnt2",
                item_fields=[FieldSpec(name="other", kind="scalar", scalar_type="u32le")],
            ),
        ],
    )
    parsed = yaml.safe_load(generate_kaitai_ksy(nested_spec))
    inner_type = parsed["types"]["groups_item"]["seq"][1]["type"]
    outer_type = parsed["seq"][-1]["type"]
    assert inner_type != outer_type
    assert parsed["types"][inner_type]["seq"][0]["type"] == "u2le"
    assert parsed["types"][outer_type]["seq"][0]["type"] == "u4le"


def test_generated_html_report_escapes_and_renders() -> None:
    samples, spec = make_rpg_save_samples()
    spec.description = '<script>alert("xss")</script>'
    html_out = generate_html_report(spec, samples)
    assert "<!DOCTYPE html>" in html_out
    assert "<svg" in html_out
    assert "Gate 1: Bit-Exact Round-Trip: PASS" in html_out
    assert "Gate 2: Anti-Passthrough: PASS" in html_out
    assert "Gate 3: Mutation Fuzzer: PASS" in html_out
    assert "<script>alert" not in html_out
    assert "&lt;script&gt;" in html_out


def test_cpp_header_shadowing_safety_and_structure() -> None:
    # Ensure field names like 'data', 'pos', 'size', 'read_u8', 'crc32_ieee' do not shadow helpers
    shadow_spec = CodecSpec(
        name="shadow_test",
        endian="le",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="53484457"),
            FieldSpec(name="size", kind="scalar", scalar_type="u16le", length_of="data"),
            FieldSpec(name="data", kind="var_bytes", length_field="size"),
            FieldSpec(name="pos", kind="scalar", scalar_type="u32le"),
            FieldSpec(name="read_u8", kind="scalar", scalar_type="u8"),
            FieldSpec(name="crc32_ieee", kind="scalar", scalar_type="u32le", crc32_of="magic..read_u8"),
        ],
    )
    hdr = generate_cpp_header(shadow_spec)
    assert "#pragma once" in hdr
    assert "CODECFORGE_GEN_RUNTIME_HELPERS" in hdr
    assert "namespace codecforge_gen" in hdr
    assert "_cf_buf" in hdr
    assert "_cf_pos" in hdr
    assert "_cf_chunk_data" in hdr
    assert "codecforge_gen::read_u8" in hdr
    assert "codecforge_gen::crc32_ieee" in hdr
    # Ensure _cf_start_ / _cf_end_ are NOT emitted for non-CRC-covered fields (would fail -Wunused-variable)
    assert "_cf_start_crc32_ieee" not in hdr
    assert "_cf_end_crc32_ieee" not in hdr

    no_crc_spec = CodecSpec(
        name="magic_only",
        fields=[FieldSpec(name="magic", kind="magic", magic_hex="4D414749")],
    )
    no_crc_hdr = generate_cpp_header(no_crc_spec)
    assert "_cf_start_" not in no_crc_hdr
    assert "_cf_end_" not in no_crc_hdr
    assert "(void)_cf_obj;" in no_crc_hdr


def test_cpp20_compile_and_execute_if_available(tmp_path: Path) -> None:
    found = _find_cpp20_compiler()
    if found is None:
        pytest.skip("No C++20 compiler with <span> available in environment")
    kind, compiler_ref = found

    rpg_samples, rpg_spec = make_rpg_save_samples()
    simple_samples, simple_spec = make_simple_save_samples()
    net_samples, net_spec = make_net_packet_samples()
    fixed_samples, fixed_spec = make_fixed_header_samples()
    corrupt = make_corrupt_samples()

    shadow_spec = CodecSpec(
        name="shadow_test",
        endian="le",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="53484457"),
            FieldSpec(name="size", kind="scalar", scalar_type="u64le", length_of="data"),
            FieldSpec(name="data", kind="var_bytes", length_field="size"),
            FieldSpec(name="pos", kind="scalar", scalar_type="u32le"),
            FieldSpec(name="read_u8", kind="scalar", scalar_type="u8"),
            FieldSpec(name="crc32_ieee", kind="scalar", scalar_type="u32le", crc32_of="magic..read_u8"),
        ],
    )

    nested_spec = CodecSpec(
        name="nested_arr",
        endian="le",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="4E415252"),
            FieldSpec(name="grp_cnt", kind="scalar", scalar_type="u8", count_of="groups"),
            FieldSpec(
                name="groups",
                kind="array",
                count_field="grp_cnt",
                item_fields=[
                    FieldSpec(name="sub_cnt", kind="scalar", scalar_type="u8", count_of="subs"),
                    FieldSpec(
                        name="subs",
                        kind="array",
                        count_field="sub_cnt",
                        item_fields=[
                            FieldSpec(name="label", kind="cstr"),
                            FieldSpec(name="val", kind="scalar", scalar_type="i16le"),
                        ],
                    ),
                ],
            ),
        ],
    )
    magic_only_spec = CodecSpec(
        name="magic_only",
        fields=[FieldSpec(name="magic", kind="magic", magic_hex="4D414749")],
    )

    for spec in (rpg_spec, simple_spec, net_spec, fixed_spec, shadow_spec, nested_spec, magic_only_spec):
        (tmp_path / f"{spec.name}.hpp").write_text(generate_cpp_header(spec), encoding="utf-8")

    (tmp_path / "rpg.bin").write_bytes(rpg_samples[0])
    (tmp_path / "simple.bin").write_bytes(simple_samples[0])
    (tmp_path / "net.bin").write_bytes(net_samples[0])
    (tmp_path / "fixed.bin").write_bytes(fixed_samples[0])
    (tmp_path / "bad_magic.bin").write_bytes(corrupt["bad_magic"][0])
    (tmp_path / "bad_crc.bin").write_bytes(corrupt["bad_crc"][0])
    (tmp_path / "bad_fixed.bin").write_bytes(corrupt["non_canonical_fixed_str"][0])
    (tmp_path / "bad_cstr.bin").write_bytes(corrupt["unterminated_cstr"][0])

    main_cpp = tmp_path / "main.cpp"
    main_cpp.write_text(
        """#include "rpg_save.hpp"
#include "simple_save.hpp"
#include "net_packet.hpp"
#include "fixed_header.hpp"
#include "shadow_test.hpp"
#include "nested_arr.hpp"
#include "magic_only.hpp"
#include <fstream>
#include <stdexcept>
#include <vector>

static std::vector<std::uint8_t> read_bin(const char* p) {
    std::ifstream ifs(p, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());
}

template <typename Fn>
static bool expect_throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main(int, char** argv) {
    // 1. rpg_save round-trip & mutation
    {
        auto raw = read_bin(argv[1]);
        auto obj = codecforge_gen::RpgSave::decode(raw);
        if (codecforge_gen::RpgSave::encode(obj) != raw) return 1;
        obj.player_name = "MutatedCppPlayer";
        obj.items.push_back({999u, 7u});
        auto mut_bytes = codecforge_gen::RpgSave::encode(obj);
        auto obj2 = codecforge_gen::RpgSave::decode(mut_bytes);
        if (codecforge_gen::RpgSave::encode(obj2) != mut_bytes) return 2;
        if (obj2.player_name != "MutatedCppPlayer" || obj2.items.size() != 2) return 3;
    }
    // 2. simple_save round-trip
    {
        auto raw = read_bin(argv[2]);
        auto obj = codecforge_gen::SimpleSave::decode(raw);
        if (codecforge_gen::SimpleSave::encode(obj) != raw) return 4;
    }
    // 3. net_packet BE round-trip & nested length backpatch
    {
        auto raw = read_bin(argv[3]);
        auto obj = codecforge_gen::NetPacket::decode(raw);
        if (codecforge_gen::NetPacket::encode(obj) != raw) return 5;
        obj.payload = {1u, 2u, 3u, 4u, 5u};
        obj.tag = "updated_tag";
        auto mut_bytes = codecforge_gen::NetPacket::encode(obj);
        auto obj2 = codecforge_gen::NetPacket::decode(mut_bytes);
        if (codecforge_gen::NetPacket::encode(obj2) != mut_bytes) return 6;
        if (obj2.body_len != 4u + 1u + 5u + 12u) return 7;
    }
    // 4. fixed_header round-trip
    {
        auto raw = read_bin(argv[4]);
        auto obj = codecforge_gen::FixedHeader::decode(raw);
        if (codecforge_gen::FixedHeader::encode(obj) != raw) return 8;
    }
    // 5. shadow_test encode/decode + u64le wraparound rejection
    {
        codecforge_gen::ShadowTest st{};
        st.data = {0xAAu, 0xBBu, 0xCCu};
        st.pos = 42u;
        st.read_u8 = 7u;
        auto packed = codecforge_gen::ShadowTest::encode(st);
        auto unpacked = codecforge_gen::ShadowTest::decode(packed);
        if (unpacked.size != 3u || unpacked.pos != 42u || unpacked.read_u8 != 7u) return 9;
        // Corrupt size to 0xFFFFFFFFFFFFFFFF (overflow test for _cf_pos + _cf_len)
        std::vector<std::uint8_t> overflow_buf = {'S','H','D','W', 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0x00};
        if (!expect_throws([&]() { (void)codecforge_gen::ShadowTest::decode(overflow_buf); })) return 10;
    }
    // 6. Corrupt sample rejections
    if (!expect_throws([&]() { (void)codecforge_gen::SimpleSave::decode(read_bin(argv[5])); })) return 11;
    if (!expect_throws([&]() { (void)codecforge_gen::SimpleSave::decode(read_bin(argv[6])); })) return 12;
    if (!expect_throws([&]() { (void)codecforge_gen::FixedHeader::decode(read_bin(argv[7])); })) return 13;
    if (!expect_throws([&]() { (void)codecforge_gen::NetPacket::decode(read_bin(argv[8])); })) return 14;
    // 7. Nested array & magic-only round-trip
    {
        codecforge_gen::NestedArr na{};
        codecforge_gen::NestedArrGroupsItem g{};
        g.subs.push_back({"inner", -12});
        na.groups.push_back(g);
        auto na_bytes = codecforge_gen::NestedArr::encode(na);
        auto na_dec = codecforge_gen::NestedArr::decode(na_bytes);
        if (na_dec.groups.size() != 1 || na_dec.groups[0].subs.size() != 1) return 15;
        if (na_dec.groups[0].subs[0].label != "inner" || na_dec.groups[0].subs[0].val != -12) return 16;

        codecforge_gen::MagicOnly mo{};
        auto mo_bytes = codecforge_gen::MagicOnly::encode(mo);
        auto mo_dec = codecforge_gen::MagicOnly::decode(mo_bytes);
        (void)mo_dec;
    }
    return 0;
}
""",
        encoding="utf-8",
    )
    exe_path = tmp_path / "test_cpp.exe"
    if kind == "gnu":
        comp = subprocess.run(
            [compiler_ref, "-std=c++20", "-Wall", "-Wextra", "-Werror", str(main_cpp), "-o", str(exe_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    else:
        bat = tmp_path / "build.bat"
        obj_path = tmp_path / "main.obj"
        bat.write_text(
            f'@echo off\ncall "{compiler_ref}" >nul\n'
            f'cl /nologo /std:c++latest /EHsc /W4 /WX /Fo:"{obj_path}" "{main_cpp}" /Fe:"{exe_path}"\n',
            encoding="utf-8",
        )
        comp = subprocess.run(
            ["cmd", "/c", str(bat)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=60,
        )
    assert comp.returncode == 0, f"{comp.stdout}\n{comp.stderr}"
    run = subprocess.run(
        [
            str(exe_path),
            str(tmp_path / "rpg.bin"),
            str(tmp_path / "simple.bin"),
            str(tmp_path / "net.bin"),
            str(tmp_path / "fixed.bin"),
            str(tmp_path / "bad_magic.bin"),
            str(tmp_path / "bad_crc.bin"),
            str(tmp_path / "bad_fixed.bin"),
            str(tmp_path / "bad_cstr.bin"),
        ],
        capture_output=True,
        timeout=10,
    )
    assert run.returncode == 0, f"C++ test binary exited with {run.returncode}"
