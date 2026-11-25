from __future__ import annotations

import struct
import zlib

import pytest

from codecforge.errors import CodecDecodeError, CodecEncodeError, SchemaValidationError
from codecforge.runtime import decode_bytes, encode_obj
from codecforge.schema import CodecSpec, FieldSpec, resolve_field_span, validate_spec
from tests.fixtures import (
    make_corrupt_samples,
    make_fixed_header_samples,
    make_net_packet_samples,
    make_rpg_save_samples,
    make_simple_save_samples,
)


def test_schema_yaml_roundtrip() -> None:
    _, spec = make_rpg_save_samples()
    yaml_text = spec.to_yaml()
    reloaded = CodecSpec.from_yaml(yaml_text)
    assert reloaded == spec
    validate_spec(reloaded)


def test_schema_validation_errors() -> None:
    # Invalid identifier & reserved keyword
    with pytest.raises(SchemaValidationError):
        validate_spec(CodecSpec(name="class", fields=[FieldSpec(name="a", kind="scalar", scalar_type="u8")]))

    with pytest.raises(SchemaValidationError):
        validate_spec(CodecSpec(name="BadName", fields=[FieldSpec(name="a", kind="scalar", scalar_type="u8")]))

    with pytest.raises(SchemaValidationError):
        validate_spec(CodecSpec(name="ok", fields=[FieldSpec(name="std", kind="scalar", scalar_type="u8")]))

    # Duplicate field names
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="dup",
                fields=[
                    FieldSpec(name="x", kind="scalar", scalar_type="u8"),
                    FieldSpec(name="x", kind="scalar", scalar_type="u8"),
                ],
            )
        )

    # bytes_rest not at end or inside array
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="rest_mid",
                fields=[
                    FieldSpec(name="tail", kind="bytes_rest"),
                    FieldSpec(name="x", kind="scalar", scalar_type="u8"),
                ],
            )
        )
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="rest_arr",
                fields=[
                    FieldSpec(name="cnt", kind="scalar", scalar_type="u8", count_of="arr"),
                    FieldSpec(
                        name="arr",
                        kind="array",
                        count_field="cnt",
                        item_fields=[FieldSpec(name="tail", kind="bytes_rest")],
                    ),
                ],
            )
        )

    # Multiple derived relations on one scalar
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="multi_rel",
                fields=[
                    FieldSpec(name="n", kind="scalar", scalar_type="u16le", length_of="s", count_of="s"),
                    FieldSpec(name="s", kind="var_str", length_field="n"),
                ],
            )
        )

    # length_of covering itself or crc32_of
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="len_self",
                fields=[
                    FieldSpec(name="n", kind="scalar", scalar_type="u16le", length_of="n..b"),
                    FieldSpec(name="b", kind="scalar", scalar_type="u8"),
                ],
            )
        )
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="len_crc",
                fields=[
                    FieldSpec(name="n", kind="scalar", scalar_type="u16le", length_of="b..c"),
                    FieldSpec(name="b", kind="scalar", scalar_type="u8"),
                    FieldSpec(name="c", kind="scalar", scalar_type="u32le", crc32_of="b"),
                ],
            )
        )

    # var_str referencing later length_field
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="late_len",
                fields=[
                    FieldSpec(name="s", kind="var_str", length_field="n"),
                    FieldSpec(name="n", kind="scalar", scalar_type="u8"),
                ],
            )
        )

    # count_of mismatch or wrong order
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(
                name="bad_cnt",
                fields=[
                    FieldSpec(name="n", kind="scalar", scalar_type="u8", count_of="arr"),
                    FieldSpec(
                        name="arr",
                        kind="array",
                        count_field="other",
                        item_fields=[FieldSpec(name="v", kind="scalar", scalar_type="u8")],
                    ),
                ],
            )
        )

    # Invalid magic hex
    with pytest.raises(SchemaValidationError):
        validate_spec(
            CodecSpec(name="bad_hex", fields=[FieldSpec(name="m", kind="magic", magic_hex="ABC")])
        )


def test_resolve_field_span() -> None:
    fields = [
        FieldSpec(name="a", kind="scalar", scalar_type="u8"),
        FieldSpec(name="b", kind="scalar", scalar_type="u8"),
        FieldSpec(name="c", kind="scalar", scalar_type="u8"),
    ]
    assert resolve_field_span(fields, "b") == ["b"]
    assert resolve_field_span(fields, "a..c") == ["a", "b", "c"]
    with pytest.raises(SchemaValidationError):
        resolve_field_span(fields, "c..a")
    with pytest.raises(SchemaValidationError):
        resolve_field_span(fields, "missing")


@pytest.mark.parametrize(
    "builder",
    [
        make_rpg_save_samples,
        make_simple_save_samples,
        make_net_packet_samples,
        make_fixed_header_samples,
    ],
)
def test_runtime_roundtrip_all_fixtures(builder) -> None:
    samples, spec = builder()
    for raw in samples:
        obj, spans = decode_bytes(spec, raw)
        assert spans[0][1] == 0
        assert spans[-1][2] == len(raw)
        reencoded = encode_obj(spec, obj)
        assert reencoded == raw


def test_runtime_nested_array_and_recomputation() -> None:
    samples, spec = make_rpg_save_samples()
    obj, _ = decode_bytes(spec, samples[0])
    # Mutate player_name length and items list WITHOUT updating name_len, item_count, or checksum
    obj["player_name"] = "MuchLongerPlayerName"
    obj["items"].append({"item_id": 777, "qty": 42})

    repacked = encode_obj(spec, obj)
    decoded, _ = decode_bytes(spec, repacked)
    assert decoded["player_name"] == "MuchLongerPlayerName"
    assert decoded["name_len"] == len("MuchLongerPlayerName".encode("utf-8"))
    assert decoded["item_count"] == 2
    assert len(decoded["items"]) == 2
    assert decoded["items"][1] == {"item_id": 777, "qty": 42}


def test_runtime_nested_length_backpatch_be() -> None:
    samples, spec = make_net_packet_samples()
    obj, _ = decode_bytes(spec, samples[0])
    obj["payload"] = b"\xaa\xbb\xcc\xdd\xee"
    obj["tag"] = "extended_tag_name"
    repacked = encode_obj(spec, obj)
    decoded, _ = decode_bytes(spec, repacked)
    assert decoded["payload_len"] == 5
    # seq (4) + payload_len (1) + payload (5) + tag ("extended_tag_name" + NUL = 18) = 28
    assert decoded["body_len"] == 4 + 1 + 5 + len("extended_tag_name") + 1


def test_runtime_corrupt_inputs_rejected() -> None:
    corrupt = make_corrupt_samples()
    for _, (raw, spec) in corrupt.items():
        with pytest.raises(CodecDecodeError):
            decode_bytes(spec, raw)


def test_runtime_nan_and_utf8_and_encode_errors() -> None:
    f_spec = CodecSpec(
        name="float_fmt",
        fields=[FieldSpec(name="x", kind="scalar", scalar_type="f32le")],
    )
    nan_bytes = struct.pack("<f", float("nan"))
    with pytest.raises(CodecDecodeError):
        decode_bytes(f_spec, nan_bytes)
    with pytest.raises(CodecEncodeError):
        encode_obj(f_spec, {"x": float("nan")})
    with pytest.raises(CodecEncodeError):
        encode_obj(f_spec, {"x": 1e100})

    s_spec = CodecSpec(
        name="str_fmt",
        fields=[
            FieldSpec(name="n", kind="scalar", scalar_type="u8", length_of="s"),
            FieldSpec(name="s", kind="var_str", length_field="n"),
        ],
    )
    with pytest.raises(CodecDecodeError):
        decode_bytes(s_spec, b"\x02\xff\xfe")

    fixed_spec = CodecSpec(
        name="fix_str",
        fields=[FieldSpec(name="s", kind="fixed_str", size=4)],
    )
    with pytest.raises(CodecEncodeError):
        encode_obj(fixed_spec, {"s": "toolong"})
    with pytest.raises(CodecEncodeError):
        encode_obj(fixed_spec, {"s": "a\x00b"})

    cstr_spec = CodecSpec(
        name="cstr_fmt",
        fields=[FieldSpec(name="s", kind="cstr")],
    )
    with pytest.raises(CodecEncodeError):
        encode_obj(cstr_spec, {"s": "bad\x00str"})


def test_runtime_crc_over_derived_scalar() -> None:
    # Verify outer CRC covers derived inner length_of field
    samples, spec = make_net_packet_samples()
    raw = samples[0]
    expected_crc = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
    actual_crc = struct.unpack(">I", raw[-4:])[0]
    assert actual_crc == expected_crc
