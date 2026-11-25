from __future__ import annotations

from codecforge.errors import (
    CodecDecodeError,
    CodecEncodeError,
    CodecForgeError,
    SchemaValidationError,
    SynthesisError,
)
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
]
