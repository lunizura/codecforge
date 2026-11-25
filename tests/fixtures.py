from __future__ import annotations

from codecforge.runtime import encode_obj
from codecforge.schema import CodecSpec, FieldSpec


def make_rpg_save_samples() -> tuple[list[bytes], CodecSpec]:
    spec = CodecSpec(
        name="rpg_save",
        endian="le",
        description="Synthetic RPG save file with variable player name, item array, and CRC32 trailer",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="43465356"),  # CFSV
            FieldSpec(name="gold", kind="scalar", scalar_type="u32le"),
            FieldSpec(name="pos_x", kind="scalar", scalar_type="f32le"),
            FieldSpec(
                name="name_len",
                kind="scalar",
                scalar_type="u16le",
                length_of="player_name",
            ),
            FieldSpec(name="player_name", kind="var_str", length_field="name_len"),
            FieldSpec(name="section_magic", kind="magic", magic_hex="44415441"),  # DATA
            FieldSpec(
                name="item_count",
                kind="scalar",
                scalar_type="u16le",
                count_of="items",
            ),
            FieldSpec(
                name="items",
                kind="array",
                count_field="item_count",
                item_fields=[
                    FieldSpec(name="item_id", kind="scalar", scalar_type="u32le"),
                    FieldSpec(name="qty", kind="scalar", scalar_type="u16le"),
                ],
            ),
            FieldSpec(
                name="checksum",
                kind="scalar",
                scalar_type="u32le",
                crc32_of="magic..items",
            ),
        ],
    )
    objects = [
        {
            "gold": 1250,
            "pos_x": 12.5,
            "player_name": "Aria",
            "items": [{"item_id": 101, "qty": 2}],
        },
        {
            "gold": 4800,
            "pos_x": -44.25,
            "player_name": "Lunizura",
            "items": [
                {"item_id": 101, "qty": 1},
                {"item_id": 205, "qty": 5},
            ],
        },
        {
            "gold": 125000,
            "pos_x": 108.75,
            "player_name": "Shadowalker99",
            "items": [
                {"item_id": 101, "qty": 3},
                {"item_id": 205, "qty": 1},
                {"item_id": 999, "qty": 12},
            ],
        },
    ]
    return [encode_obj(spec, obj) for obj in objects], spec


def make_simple_save_samples() -> tuple[list[bytes], CodecSpec]:
    spec = CodecSpec(
        name="simple_save",
        endian="le",
        description="Simple save file without arrays for offline heuristic synthesis",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="53415631"),  # SAV1
            FieldSpec(name="score", kind="scalar", scalar_type="u32le"),
            FieldSpec(name="coord_x", kind="scalar", scalar_type="f32le"),
            FieldSpec(name="bio_len", kind="scalar", scalar_type="u16le", length_of="bio"),
            FieldSpec(name="bio", kind="var_str", length_field="bio_len"),
            FieldSpec(name="end_magic", kind="magic", magic_hex="454E4421"),  # END!
            FieldSpec(name="level", kind="scalar", scalar_type="u16le"),
            FieldSpec(name="checksum", kind="scalar", scalar_type="u32le", crc32_of="magic..level"),
        ],
    )
    objects = [
        {"score": 1500, "coord_x": 3.5, "bio": "Hero", "level": 5},
        {"score": 8200, "coord_x": -18.25, "bio": " Nightblade", "level": 19},
        {"score": 140500, "coord_x": 240.125, "bio": "Grandmaster_Z", "level": 60},
    ]
    return [encode_obj(spec, obj) for obj in objects], spec


def make_net_packet_samples() -> tuple[list[bytes], CodecSpec]:
    spec = CodecSpec(
        name="net_packet",
        endian="be",
        description="Big-endian network frame with outer body_len, inner payload_len, cstr, and BE CRC32",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="504B5431"),  # PKT1
            FieldSpec(
                name="body_len",
                kind="scalar",
                scalar_type="u16be",
                length_of="seq..tag",
            ),
            FieldSpec(name="seq", kind="scalar", scalar_type="u32be"),
            FieldSpec(
                name="payload_len",
                kind="scalar",
                scalar_type="u8",
                length_of="payload",
            ),
            FieldSpec(name="payload", kind="var_bytes", length_field="payload_len"),
            FieldSpec(name="tag", kind="cstr"),
            FieldSpec(name="crc", kind="scalar", scalar_type="u32be", crc32_of="magic..tag"),
        ],
    )
    objects = [
        {"seq": 1, "payload": b"\x01\x02\x03", "tag": "ping"},
        {"seq": 42, "payload": b"\xde\xad\xbe\xef\xca\xfe", "tag": "sync_ok"},
        {"seq": 1337, "payload": b"\x99", "tag": "heartbeat_ack"},
    ]
    return [encode_obj(spec, obj) for obj in objects], spec


def make_fixed_header_samples() -> tuple[list[bytes], CodecSpec]:
    spec = CodecSpec(
        name="fixed_header",
        endian="le",
        description="Fixed-width header format with NUL-padded label, fixed bytes, version, and CRC32",
        fields=[
            FieldSpec(name="magic", kind="magic", magic_hex="48445230"),  # HDR0
            FieldSpec(name="label", kind="fixed_str", size=12, pad_byte_hex="00"),
            FieldSpec(name="flags", kind="fixed_bytes", size=4),
            FieldSpec(name="version", kind="scalar", scalar_type="u16le"),
            FieldSpec(
                name="checksum",
                kind="scalar",
                scalar_type="u32le",
                crc32_of="magic..version",
            ),
        ],
    )
    objects = [
        {"label": "alpha", "flags": b"\x01\x00\x00\x80", "version": 1},
        {"label": "beta_v2", "flags": b"\x02\x04\x00\x00", "version": 2},
        {"label": "release12345", "flags": b"\xff\x01\x02\x03", "version": 10},
    ]
    return [encode_obj(spec, obj) for obj in objects], spec


def make_corrupt_samples() -> dict[str, tuple[bytes, CodecSpec]]:
    simple_samples, simple_spec = make_simple_save_samples()
    fixed_samples, fixed_spec = make_fixed_header_samples()
    net_samples, net_spec = make_net_packet_samples()

    base_simple = bytearray(simple_samples[0])
    bad_magic = bytes(b"XXXX" + base_simple[4:])

    bad_crc = bytearray(simple_samples[0])
    bad_crc[-1] ^= 0xFF

    trailing = simple_samples[0] + b"\xaa\xbb"

    # Non-canonical fixed_str: byte after first NUL in label (offset 4..16)
    bad_fixed = bytearray(fixed_samples[0])
    # "alpha\x00\x00..." -> put non-zero byte at index 4 + 8 = 12
    bad_fixed[12] = 0x42

    # Unterminated cstr: remove trailing NUL before 4-byte CRC
    bad_cstr = net_samples[0][:-5] + b"X" + net_samples[0][-4:]

    return {
        "bad_magic": (bad_magic, simple_spec),
        "bad_crc": (bytes(bad_crc), simple_spec),
        "trailing_bytes": (trailing, simple_spec),
        "non_canonical_fixed_str": (bytes(bad_fixed), fixed_spec),
        "unterminated_cstr": (bad_cstr, net_spec),
    }
