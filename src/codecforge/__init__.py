from __future__ import annotations

from codecforge.codegen_cpp import generate_cpp_header
from codecforge.codegen_ksy import generate_kaitai_ksy
from codecforge.codegen_py import generate_python_module
from codecforge.errors import (
    CodecDecodeError,
    CodecEncodeError,
    CodecForgeError,
    SchemaValidationError,
    SynthesisError,
)
from codecforge.llm_client import (
    GeminiInteractionsProvider,
    LLMProvider,
    OpenAICompatibleProvider,
    ScriptedMockProvider,
    extract_json_object,
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
from codecforge.report_html import generate_html_report
from codecforge.runtime import decode_bytes, encode_obj
from codecforge.schema import (
    CodecSpec,
    FieldSpec,
    resolve_field_span,
    validate_spec,
)
from codecforge.synthesizer import (
    synthesize_codec,
    synthesize_heuristic,
    synthesize_with_llm,
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
    "LLMProvider",
    "GeminiInteractionsProvider",
    "OpenAICompatibleProvider",
    "ScriptedMockProvider",
    "extract_json_object",
    "synthesize_codec",
    "synthesize_heuristic",
    "synthesize_with_llm",
    "generate_python_module",
    "generate_cpp_header",
    "generate_kaitai_ksy",
    "generate_html_report",
]
