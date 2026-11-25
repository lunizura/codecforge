from __future__ import annotations

import copy

from codecforge.oracle import verify_codec
from codecforge.schema import CodecSpec, FieldSpec
from tests.fixtures import (
    make_fixed_header_samples,
    make_net_packet_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


def test_oracle_passes_all_valid_fixtures() -> None:
    for builder in (
        make_rpg_save_samples,
        make_simple_save_samples,
        make_net_packet_samples,
        make_fixed_header_samples,
    ):
        samples, spec = builder()
        res = verify_codec(spec, samples)
        assert res.passed, res.failures
        assert res.gate1_roundtrip_passed
        assert res.gate2_coverage_passed
        assert res.gate3_mutation_passed


def test_oracle_gate1_catches_bad_magic_and_bad_crc() -> None:
    samples, spec = make_rpg_save_samples()
    bad_spec = copy.deepcopy(spec)
    bad_spec.fields[0].magic_hex = "DEADBEEF"
    res = verify_codec(bad_spec, samples)
    assert not res.passed
    assert not res.gate1_roundtrip_passed
    assert any("Gate 1" in f for f in res.failures)


def test_oracle_gate2_rejects_lazy_bytes_rest_and_missing_magic() -> None:
    samples, spec = make_simple_save_samples()

    lazy_spec = CodecSpec(
        name="lazy_blob",
        fields=[FieldSpec(name="blob", kind="bytes_rest")],
    )
    res = verify_codec(lazy_spec, samples)
    assert not res.passed
    assert res.gate1_roundtrip_passed
    assert not res.gate2_coverage_passed
    assert any("passthrough" in f.lower() or "opaque" in f.lower() for f in res.failures)

    # Multi-field opaque schema missing magic at offset 0
    no_magic_spec = CodecSpec(
        name="no_magic",
        fields=[
            FieldSpec(name="header", kind="fixed_bytes", size=4),
            FieldSpec(name="rest", kind="bytes_rest"),
        ],
    )
    res2 = verify_codec(no_magic_spec, samples)
    assert not res2.passed
    assert not res2.gate2_coverage_passed
    assert any("magic" in f.lower() for f in res2.failures)


def test_oracle_gate3_catches_missing_length_of_and_crc32_of() -> None:
    samples, spec = make_simple_save_samples()

    # Omit length_of on bio_len -> mutating bio by +3 bytes breaks Gate 3
    no_len_spec = copy.deepcopy(spec)
    no_len_spec.fields[3].length_of = None
    res_len = verify_codec(no_len_spec, samples)
    assert not res_len.passed
    assert res_len.gate1_roundtrip_passed
    assert res_len.gate2_coverage_passed
    assert not res_len.gate3_mutation_passed
    assert any("Gate 3" in f for f in res_len.failures)

    # Omit crc32_of on checksum -> Gate 3 catches missing CRC recomputation
    no_crc_spec = copy.deepcopy(spec)
    no_crc_spec.fields[-1].crc32_of = None
    res_crc = verify_codec(no_crc_spec, samples)
    assert not res_crc.passed
    assert res_crc.gate1_roundtrip_passed
    assert not res_crc.gate3_mutation_passed
    assert any("crc32_of" in f for f in res_crc.failures)


def test_oracle_gate3_catches_missing_count_of() -> None:
    samples, spec = make_rpg_save_samples()
    no_cnt_spec = copy.deepcopy(spec)
    no_cnt_spec.fields[6].count_of = None
    res = verify_codec(no_cnt_spec, samples)
    assert not res.passed
    assert not res.gate3_mutation_passed
    assert any("Gate 3" in f for f in res.failures)
