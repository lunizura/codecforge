from __future__ import annotations

from codecforge.errors import (
    CodecDecodeError,
    CodecEncodeError,
    CodecForgeError,
    SchemaValidationError,
    SynthesisError,
)
from codecforge.oracle import OracleResult, verify_codec
from codecforge.probe import (
    AlignedSegment,
    ChecksumCandidate,
    LengthRelationCandidate,
    ProbeReport,
    align_samples,
    detect_checksums,
    detect_lengths,
    probe_samples,
    shannon_entropy,
    sliding_entropy,
)
from codecforge.runtime import decode_bytes, encode_obj
from codecforge.schema import (
    CodecSpec,
    FieldSpec,
    resolve_field_span,
    validate_spec,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "CodecForgeError",
    "SchemaValidationError",
    "CodecDecodeError",
    "CodecEncodeError",
    "SynthesisError",
    "CodecSpec",
    "FieldSpec",
    "resolve_field_span",
    "validate_spec",
    "decode_bytes",
    "encode_obj",
    "AlignedSegment",
    "ChecksumCandidate",
    "LengthRelationCandidate",
    "ProbeReport",
    "align_samples",
    "detect_checksums",
    "detect_lengths",
    "probe_samples",
    "shannon_entropy",
    "sliding_entropy",
    "OracleResult",
    "verify_codec",
]
