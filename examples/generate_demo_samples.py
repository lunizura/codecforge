from __future__ import annotations

import struct
import zlib
from pathlib import Path


def _pack_simple_save(score: int, coord_x: float, bio: str, level: int) -> bytes:
    bio_bytes = bio.encode("utf-8")
    body = b"".join([
        b"SAV1",
        struct.pack("<I", score),
        struct.pack("<f", coord_x),
        struct.pack("<H", len(bio_bytes)),
        bio_bytes,
        b"END!",
        struct.pack("<H", level),
    ])
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("<I", crc)


def main() -> None:
    out_dir = Path(__file__).resolve().parent / "samples"
    out_dir.mkdir(parents=True, exist_ok=True)
    samples = [
        _pack_simple_save(1500, 3.5, "Hero", 5),
        _pack_simple_save(8200, -18.25, "Nightblade", 19),
        _pack_simple_save(140500, 240.125, "Grandmaster_Z", 60),
    ]
    for idx, data in enumerate(samples, start=1):
        target = out_dir / f"save_0{idx}.bin"
        target.write_bytes(data)
        print(f"Wrote {target} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
