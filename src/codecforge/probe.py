from __future__ import annotations

import difflib
import math
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal

from codecforge.errors import CodecForgeError
from codecforge.schema import ScalarType


@dataclass
class AlignedSegment:
    kind: Literal["const", "fixed_var", "shifted_var"]
    sample_slices: list[tuple[int, int]]
    const_bytes_hex: str | None = None
    fixed_size: int | None = None
    entropy_mean: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "sample_slices": [list(s) for s in self.sample_slices],
            "const_bytes_hex": self.const_bytes_hex,
            "fixed_size": self.fixed_size,
            "entropy_mean": round(self.entropy_mean, 4),
            "notes": list(self.notes),
        }


@dataclass
class LengthRelationCandidate:
    sample0_offset: int
    width: int
    scalar_type: ScalarType
    target_kind: Literal["segment_index", "remaining_body", "total_file"]
    target_segment_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample0_offset": self.sample0_offset,
            "width": self.width,
            "scalar_type": self.scalar_type,
            "target_kind": self.target_kind,
            "target_segment_index": self.target_segment_index,
        }


@dataclass
class ChecksumCandidate:
    position: Literal["trailer_4"]
    sample0_offset: int
    scalar_type: Literal["u32le", "u32be"]
    covered_slice_desc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "sample0_offset": self.sample0_offset,
            "scalar_type": self.scalar_type,
            "covered_slice_desc": self.covered_slice_desc,
        }


@dataclass
class ProbeReport:
    sample_count: int
    sample_sizes: list[int]
    overall_entropy: float
    segments: list[AlignedSegment]
    length_candidates: list[LengthRelationCandidate]
    checksum_candidates: list[ChecksumCandidate]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "sample_sizes": list(self.sample_sizes),
            "overall_entropy": round(self.overall_entropy, 4),
            "segments": [seg.to_dict() for seg in self.segments],
            "length_candidates": [c.to_dict() for c in self.length_candidates],
            "checksum_candidates": [c.to_dict() for c in self.checksum_candidates],
        }

    def to_prompt_summary(self, samples: list[bytes], max_hex_bytes: int = 128) -> str:
        lines: list[str] = [
            f"Samples: {self.sample_count} files, sizes={self.sample_sizes}, "
            f"mean_entropy={self.overall_entropy:.3f} bits/byte",
            "",
            "Checksum Candidates:",
        ]
        if self.checksum_candidates:
            for c in self.checksum_candidates:
                lines.append(
                    f"  - {c.position} @ sample0+0x{c.sample0_offset:x} "
                    f"({c.scalar_type}, covers {c.covered_slice_desc})"
                )
        else:
            lines.append("  - none detected")

        lines.append("")
        lines.append("Length Prefix Candidates:")
        if self.length_candidates:
            for c in self.length_candidates:
                target = (
                    f"segment[{c.target_segment_index}]"
                    if c.target_segment_index is not None
                    else c.target_kind
                )
                lines.append(
                    f"  - sample0+0x{c.sample0_offset:x} ({c.scalar_type}, {c.width}B) -> {target}"
                )
        else:
            lines.append("  - none detected")

        lines.append("")
        lines.append("Aligned Segments:")
        for idx, seg in enumerate(self.segments):
            slices_str = ", ".join(f"[{s}:{e}]({e - s}B)" for s, e in seg.sample_slices)
            if seg.kind == "const" and seg.const_bytes_hex is not None:
                raw = bytes.fromhex(seg.const_bytes_hex)
                ascii_hint = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in raw)
                lines.append(
                    f"  [{idx}] {seg.kind}: hex={seg.const_bytes_hex} ascii='{ascii_hint}' "
                    f"slices={slices_str}"
                )
            else:
                preview_hex = ""
                if samples and seg.sample_slices:
                    s0, e0 = seg.sample_slices[0]
                    chunk = samples[0][s0 : min(e0, s0 + 32)]
                    preview_hex = chunk.hex()
                lines.append(
                    f"  [{idx}] {seg.kind}: fixed_size={seg.fixed_size} "
                    f"entropy={seg.entropy_mean:.2f} slices={slices_str} sample0_hex={preview_hex}"
                )

        lines.append("")
        lines.append("Sample Hex Previews:")
        for idx, sample in enumerate(samples):
            head = sample[:max_hex_bytes]
            ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in head)
            suffix = "..." if len(sample) > max_hex_bytes else ""
            lines.append(f"  sample[{idx}] ({len(sample)}B): {head.hex()}{suffix}")
            lines.append(f"  ascii[{idx}]: {ascii_str}{suffix}")

        return "\n".join(lines)


def shannon_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def sliding_entropy(
    data: bytes, window: int = 64, step: int = 32
) -> list[tuple[int, float]]:
    if not data:
        return [(0, 0.0)]
    if len(data) <= window:
        return [(0, shannon_entropy(data))]
    out: list[tuple[int, float]] = []
    for offset in range(0, len(data) - window + 1, step):
        out.append((offset, shannon_entropy(data[offset : offset + window])))
    return out


def detect_checksums(samples: list[bytes]) -> list[ChecksumCandidate]:
    if len(samples) < 2 or not all(len(s) >= 5 for s in samples):
        return []
    candidates: list[ChecksumCandidate] = []
    for st, fmt in (("u32le", "<I"), ("u32be", ">I")):
        matched = True
        for s in samples:
            calc = zlib.crc32(s[:-4]) & 0xFFFFFFFF
            stored = struct.unpack(fmt, s[-4:])[0]
            if calc != stored:
                matched = False
                break
        if matched:
            candidates.append(
                ChecksumCandidate(
                    position="trailer_4",
                    sample0_offset=len(samples[0]) - 4,
                    scalar_type=st,  # type: ignore[arg-type]
                    covered_slice_desc="0..-4",
                )
            )
    return candidates


def _make_var_segment(
    work: list[bytes], slices: list[tuple[int, int]]
) -> AlignedSegment:
    lengths = [e - s for s, e in slices]
    ent = sum(shannon_entropy(work[k][s:e]) for k, (s, e) in enumerate(slices)) / len(work)
    if len(set(lengths)) == 1:
        return AlignedSegment(
            kind="fixed_var",
            sample_slices=slices,
            const_bytes_hex=None,
            fixed_size=lengths[0],
            entropy_mean=ent,
        )
    return AlignedSegment(
        kind="shifted_var",
        sample_slices=slices,
        const_bytes_hex=None,
        fixed_size=None,
        entropy_mean=ent,
    )


def align_samples(
    samples: list[bytes], strip_trailer_bytes: int = 0
) -> list[AlignedSegment]:
    if not samples:
        return []
    work = [
        s[: len(s) - strip_trailer_bytes] if strip_trailer_bytes else s
        for s in samples
    ]
    s0 = work[0]
    n0 = len(s0)
    if n0 == 0 and all(len(w) == 0 for w in work):
        return []

    # Step A: Leading Magic Prefix at offset 0
    min_len = min(len(w) for w in work)
    p_len = 0
    while p_len < min_len and all(w[p_len] == s0[p_len] for w in work[1:]):
        p_len += 1

    if p_len >= 2:
        if all(0x20 <= b <= 0x7E for b in s0[0:2]):
            while p_len > 2 and not (0x20 <= s0[p_len - 1] <= 0x7E):
                p_len -= 1
    else:
        p_len = 0

    # Step B: Interior Synchronization Anchors via SequenceMatcher
    inv = [True] * n0
    for i in range(p_len):
        inv[i] = False

    for w in work[1:]:
        sm = difflib.SequenceMatcher(None, s0[p_len:], w[p_len:], autojunk=False)
        matched = [False] * n0
        for blk in sm.get_matching_blocks():
            a_start = p_len + blk.a
            for i in range(a_start, a_start + blk.size):
                matched[i] = True
        for i in range(p_len, n0):
            inv[i] = inv[i] and matched[i]

    interior_runs: list[tuple[int, int]] = []
    i = p_len
    while i < n0:
        if not inv[i]:
            i += 1
            continue
        j = i
        while j < n0 and inv[j]:
            j += 1
        needle = s0[i:j]
        length = j - i
        is_nonuniform_4 = length >= 4 and len(set(needle)) >= 2
        is_ascii_3 = length >= 3 and all(0x20 <= x <= 0x7E for x in needle)
        if is_nonuniform_4 or is_ascii_3:
            interior_runs.append((i, j))
        i = j

    # Step C: Monotonic Multi-Sample Anchor Resolution
    candidates: list[tuple[int, int]] = ([(0, p_len)] if p_len >= 2 else []) + interior_runs
    cursors = [0] * len(work)
    segments: list[AlignedSegment] = []

    for a, b in candidates:
        needle = s0[a:b]
        width = b - a
        positions: list[int] = []
        valid = True
        for k, w in enumerate(work):
            if k == 0:
                pos_k = a
            else:
                pos_k = w.find(needle, cursors[k])
            if pos_k == -1 or pos_k < cursors[k]:
                valid = False
                break
            if a == 0 and pos_k != 0:
                valid = False
                break
            positions.append(pos_k)

        if not valid:
            continue

        gap_slices = [(cursors[k], positions[k]) for k in range(len(work))]
        if any(e > s for s, e in gap_slices):
            segments.append(_make_var_segment(work, gap_slices))

        anchor_slices = [(positions[k], positions[k] + width) for k in range(len(work))]
        segments.append(
            AlignedSegment(
                kind="const",
                sample_slices=anchor_slices,
                const_bytes_hex=needle.hex().upper(),
                fixed_size=width,
                entropy_mean=shannon_entropy(needle),
            )
        )
        cursors = [positions[k] + width for k in range(len(work))]

    tail_slices = [(cursors[k], len(work[k])) for k in range(len(work))]
    if any(e > s for s, e in tail_slices):
        segments.append(_make_var_segment(work, tail_slices))

    return segments


def detect_lengths(
    samples: list[bytes],
    segments: list[AlignedSegment],
    strip_trailer_bytes: int = 0,
) -> list[LengthRelationCandidate]:
    if len(samples) < 2:
        return []
    work = [
        s[: len(s) - strip_trailer_bytes] if strip_trailer_bytes else s
        for s in samples
    ]
    candidates: list[LengthRelationCandidate] = []
    rule1a_offsets: set[int] = set()
    claimed_sample0_offsets: set[int] = set()

    # Rule 1a: Adjacent preceding length prefix before a shifted_var segment
    for j in range(1, len(segments)):
        seg = segments[j]
        if seg.kind != "shifted_var":
            continue
        target_lens = [e - s for s, e in seg.sample_slices]
        if len(set(target_lens)) < 2:
            continue
        prev = segments[j - 1]
        if prev.kind != "fixed_var" or prev.fixed_size is None or prev.fixed_size < 1:
            continue

        for width, st, fmt in (
            (2, "u16le", "<H"),
            (2, "u16be", ">H"),
            (4, "u32le", "<I"),
            (4, "u32be", ">I"),
            (1, "u8", "<B"),
        ):
            if prev.fixed_size < width:
                continue
            matched = True
            for k, w in enumerate(work):
                _, pe = prev.sample_slices[k]
                val = struct.unpack_from(fmt, w, pe - width)[0]
                if val != target_lens[k]:
                    matched = False
                    break
            if matched:
                s0_off = prev.sample_slices[0][1] - width
                rule1a_offsets.add(s0_off)
                claimed_sample0_offsets.add(s0_off)
                candidates.append(
                    LengthRelationCandidate(
                        sample0_offset=s0_off,
                        width=width,
                        scalar_type=st,  # type: ignore[arg-type]
                        target_kind="segment_index",
                        target_segment_index=j,
                    )
                )
                break

    # Rule 1b: Embedded length prefix inside the fixed-offset head of a shifted_var segment
    for j, seg in enumerate(segments):
        if seg.kind != "shifted_var":
            continue
        if any(c.target_kind == "segment_index" and c.target_segment_index == j for c in candidates):
            continue
        seg_lens = [e - s for s, e in seg.sample_slices]
        if len(set(seg_lens)) < 2:
            continue
        min_seg_len = min(seg_lens)
        found_embedded = False
        for rel in range(min_seg_len):
            s0_off = seg.sample_slices[0][0] + rel
            if s0_off in claimed_sample0_offsets:
                continue
            for width, st, fmt in (
                (2, "u16le", "<H"),
                (2, "u16be", ">H"),
                (4, "u32le", "<I"),
                (4, "u32be", ">I"),
                (1, "u8", "<B"),
            ):
                if rel + width > min_seg_len:
                    continue
                vals: list[int] = []
                matched = True
                for k, w in enumerate(work):
                    sk, ek = seg.sample_slices[k]
                    val = struct.unpack_from(fmt, w, sk + rel)[0]
                    if val != ek - (sk + rel + width):
                        matched = False
                        break
                    vals.append(val)
                if matched and len(set(vals)) >= 2:
                    claimed_sample0_offsets.add(s0_off)
                    candidates.append(
                        LengthRelationCandidate(
                            sample0_offset=s0_off,
                            width=width,
                            scalar_type=st,  # type: ignore[arg-type]
                            target_kind="segment_index",
                            target_segment_index=j,
                        )
                    )
                    found_embedded = True
                    break
            if found_embedded:
                break

    # Rule 2: Header remaining-body / total-file length field
    if len(set(len(s) for s in samples)) >= 2:
        for seg in segments:
            if seg.kind not in ("fixed_var", "shifted_var"):
                continue
            s0_start = seg.sample_slices[0][0]
            if s0_start >= 16:
                continue
            min_seg_len = min(e - s for s, e in seg.sample_slices)
            scan_limit = min(min_seg_len, 16 - s0_start)
            for rel in range(scan_limit):
                s0_off = s0_start + rel
                if s0_off in rule1a_offsets:
                    continue
                for width, st, fmt in (
                    (2, "u16le", "<H"),
                    (2, "u16be", ">H"),
                    (4, "u32le", "<I"),
                    (4, "u32be", ">I"),
                ):
                    if rel + width > min_seg_len:
                        continue
                    rem_match = True
                    tot_match = True
                    for k, w in enumerate(work):
                        seg_start_k = seg.sample_slices[k][0]
                        val = struct.unpack_from(fmt, w, seg_start_k + rel)[0]
                        if val != len(w) - (seg_start_k + rel + width):
                            rem_match = False
                        if val != len(samples[k]):
                            tot_match = False
                    if rem_match:
                        candidates.append(
                            LengthRelationCandidate(
                                sample0_offset=s0_off,
                                width=width,
                                scalar_type=st,  # type: ignore[arg-type]
                                target_kind="remaining_body",
                                target_segment_index=None,
                            )
                        )
                        break
                    if tot_match:
                        candidates.append(
                            LengthRelationCandidate(
                                sample0_offset=s0_off,
                                width=width,
                                scalar_type=st,  # type: ignore[arg-type]
                                target_kind="total_file",
                                target_segment_index=None,
                            )
                        )
                        break

    return candidates


def probe_samples(samples: list[bytes]) -> ProbeReport:
    if len(samples) < 2:
        raise CodecForgeError("probe_samples requires at least 2 binary samples")
    checksum_candidates = detect_checksums(samples)
    strip_n = 4 if checksum_candidates else 0
    segments = align_samples(samples, strip_trailer_bytes=strip_n)
    length_candidates = detect_lengths(samples, segments, strip_trailer_bytes=strip_n)
    overall_entropy = sum(shannon_entropy(s) for s in samples) / len(samples)
    return ProbeReport(
        sample_count=len(samples),
        sample_sizes=[len(s) for s in samples],
        overall_entropy=overall_entropy,
        segments=segments,
        length_candidates=length_candidates,
        checksum_candidates=checksum_candidates,
    )
