from __future__ import annotations

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
    make_fixed_header_samples,
    make_net_packet_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


def _find_cpp20_compiler() -> str | None:
    for name in ("g++", "clang++"):
        exe = shutil.which(name)
        if not exe:
            continue
        # Probe C++20 <span> support
        proc = subprocess.run(
            [exe, "-std=c++20", "-x", "c++", "-", "-fsyntax-only"],
            input=b"#include <span>\nint main() { return 0; }\n",
            capture_output=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return exe
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
    # Ensure field names like 'data', 'pos', 'size', 'crc', 'items' do not shadow _cf_ locals
    shadow_spec = CodecSpec(
        name="shadow_test",
        endian="le",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="53484457"),
            FieldSpec(name="size", kind="scalar", scalar_type="u16le", length_of="data"),
            FieldSpec(name="data", kind="var_bytes", length_field="size"),
            FieldSpec(name="pos", kind="scalar", scalar_type="u32le"),
            FieldSpec(name="crc", kind="scalar", scalar_type="u32le", crc32_of="magic..pos"),
        ],
    )
    hdr = generate_cpp_header(shadow_spec)
    assert "#pragma once" in hdr
    assert "namespace codecforge_gen" in hdr
    assert "_cf_buf" in hdr
    assert "_cf_pos" in hdr
    assert "_cf_chunk_data" in hdr
    assert "crc32_ieee" in hdr
    assert "reinterpret_cast" not in hdr or "reinterpret_cast<const char*>" in hdr


def test_cpp20_compile_and_execute_if_available(tmp_path: Path) -> None:
    compiler = _find_cpp20_compiler()
    if compiler is None:
        pytest.skip("No C++20 compiler with <span> available in environment")

    samples, spec = make_rpg_save_samples()
    hdr = generate_cpp_header(spec)
    hdr_path = tmp_path / "rpg_save.hpp"
    hdr_path.write_text(hdr, encoding="utf-8")

    sample_path = tmp_path / "sample0.bin"
    sample_path.write_bytes(samples[0])

    main_cpp = tmp_path / "main.cpp"
    main_cpp.write_text(
        """#include "rpg_save.hpp"
#include <cassert>
#include <fstream>
#include <vector>

int main(int argc, char** argv) {
    std::ifstream ifs(argv[1], std::ios::binary);
    std::vector<std::uint8_t> raw((std::istreambuf_iterator<char>(ifs)),
                                  std::istreambuf_iterator<char>());
    auto obj = codecforge_gen::RpgSave::decode(raw);
    auto repacked = codecforge_gen::RpgSave::encode(obj);
    assert(repacked == raw);
    obj.player_name = "MutatedCppPlayer";
    obj.items.push_back({999u, 7u});
    auto mut_bytes = codecforge_gen::RpgSave::encode(obj);
    auto obj2 = codecforge_gen::RpgSave::decode(mut_bytes);
    auto repacked2 = codecforge_gen::RpgSave::encode(obj2);
    assert(repacked2 == mut_bytes);
    assert(obj2.player_name == "MutatedCppPlayer");
    assert(obj2.items.size() == 2);
    return 0;
}
""",
        encoding="utf-8",
    )
    exe_path = tmp_path / "test_cpp.exe"
    comp = subprocess.run(
        [compiler, "-std=c++20", "-Wall", "-Wextra", str(main_cpp), "-o", str(exe_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert comp.returncode == 0, comp.stderr
    run = subprocess.run([str(exe_path), str(sample_path)], capture_output=True, timeout=10)
    assert run.returncode == 0
