from __future__ import annotations

import math

import pytest

from codecforge.errors import CodecForgeError
from codecforge.probe import (
    align_samples,
    detect_checksums,
    detect_lengths,
    probe_samples,
    shannon_entropy,
    sliding_entropy,
)
from codecforge.runtime import encode_obj
from codecforge.schema import CodecSpec, FieldSpec
from tests.fixtures import (
    make_fixed_header_samples,
    make_net_packet_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


def test_entropy_math() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 64) == 0.0
    assert math.isclose(shannon_entropy(b"\x00\xff" * 32), 1.0, rel_tol=1e-6)
    assert math.isclose(shannon_entropy(bytes(range(256))), 8.0, rel_tol=1e-6)

    windows = sliding_entropy(bytes(range(128)), window=64, step=32)
    assert len(windows) == 3
    assert windows[0][0] == 0
    assert windows[1][0] == 32
    assert windows[2][0] == 64
    assert all(math.isclose(ent, 6.0, rel_tol=1e-6) for _, ent in windows)

    short_windows = sliding_entropy(b"ABCD", window=64, step=32)
    assert len(short_windows) == 1
    assert math.isclose(short_windows[0][1], 2.0, rel_tol=1e-6)


def test_detect_checksums_le_and_be() -> None:
    simple_samples, _ = make_simple_save_samples()
    le_cands = detect_checksums(simple_samples)
    assert len(le_cands) == 1
    assert le_cands[0].scalar_type == "u32le"
    assert le_cands[0].covered_slice_desc == "0..-4"

    net_samples, _ = make_net_packet_samples()
    be_cands = detect_checksums(net_samples)
    assert len(be_cands) == 1
    assert be_cands[0].scalar_type == "u32be"

    # Non-checksum data returns empty
    assert detect_checksums([b"hello world 1", b"hello world 2"]) == []


def test_align_samples_avoids_zero_padding_trap_and_aligns_shifted_strings() -> None:
    # 1250 = e2 04 00 00, 4800 = c0 12 00 00 share \x00\x00 inside u32le!
    rpg_samples, _ = make_rpg_save_samples()
    segs = align_samples(rpg_samples, strip_trailer_bytes=4)
    # Must NOT split inside gold (offset 4..8) on the shared \x00\x00 bytes
    assert segs[0].kind == "const"
    assert segs[0].const_bytes_hex == "43465356"
    assert segs[1].kind == "shifted_var"
    assert segs[1].sample_slices == [(4, 18), (4, 22), (4, 27)]
    assert segs[2].kind == "const"
    assert segs[2].const_bytes_hex == "44415441"


def test_detect_lengths_segment_and_remaining_body() -> None:
    simple_samples, _ = make_simple_save_samples()
    report = probe_samples(simple_samples)
    assert report.sample_count == 3
    assert len(report.checksum_candidates) == 1
    assert len(report.length_candidates) == 1
    lc = report.length_candidates[0]
    assert lc.scalar_type == "u16le"
    assert lc.target_kind == "segment_index"
    assert lc.target_segment_index == 1
    assert lc.sample0_offset == 12

    # Big-endian net packet has remaining_body length prefix at offset 4 (u16be)
    net_samples, _ = make_net_packet_samples()
    net_segs = align_samples(net_samples, strip_trailer_bytes=4)
    net_lens = detect_lengths(net_samples, net_segs, strip_trailer_bytes=4)
    assert any(
        c.target_kind == "remaining_body" and c.scalar_type == "u16be" and c.sample0_offset == 4
        for c in net_lens
    )


def test_probe_fixed_header_and_prompt_summary() -> None:
    fixed_samples, _ = make_fixed_header_samples()
    report = probe_samples(fixed_samples)
    assert report.segments[0].kind == "const"
    assert report.segments[0].const_bytes_hex == "48445230"
    summary = report.to_prompt_summary(fixed_samples)
    assert "HDR0" in summary
    assert "u32le" in summary

    with pytest.raises(CodecForgeError):
        probe_samples([fixed_samples[0]])


def test_detect_lengths_rule1b_with_empty_var_str() -> None:
    spec = CodecSpec(
        name="empty_var",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="454D5031"),
            FieldSpec(name="n", kind="scalar", scalar_type="u16le", length_of="s"),
            FieldSpec(name="s", kind="var_str", length_field="n"),
        ],
    )
    samples = [
        encode_obj(spec, {"s": ""}),
        encode_obj(spec, {"s": "hello"}),
        encode_obj(spec, {"s": "world!"}),
    ]
    segs = align_samples(samples)
    lens = detect_lengths(samples, segs)
    assert any(
        c.target_kind == "segment_index"
        and c.target_segment_index == 1
        and c.scalar_type == "u16le"
        and c.sample0_offset == 4
        for c in lens
    )


def test_detect_lengths_rule2_u32be_does_not_emit_overlapping_u16be() -> None:
    spec = CodecSpec(
        name="be32_frame",
        endian="be",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="46524D31"),
            FieldSpec(name="body_len", kind="scalar", scalar_type="u32be", length_of="ver..msg"),
            FieldSpec(name="ver", kind="scalar", scalar_type="u16be"),
            FieldSpec(name="msg", kind="cstr"),
        ],
    )
    samples = [
        encode_obj(spec, {"ver": 1, "msg": "hi"}),
        encode_obj(spec, {"ver": 2, "msg": "hello world"}),
        encode_obj(spec, {"ver": 3, "msg": "testing123456"}),
    ]
    segs = align_samples(samples)
    lens = detect_lengths(samples, segs)
    rem_cands = [c for c in lens if c.target_kind == "remaining_body"]
    assert len(rem_cands) == 1
    assert rem_cands[0].sample0_offset == 4
    assert rem_cands[0].scalar_type == "u32be"
