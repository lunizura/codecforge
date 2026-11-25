class CodecForgeError(Exception):
    """Base error for all codecforge failures."""


class SchemaValidationError(CodecForgeError):
    """Raised when a CodecSpec violates naming, type, ordering, or span rules."""


class CodecDecodeError(CodecForgeError):
    """Raised when binary input fails magic, bounds, UTF-8, canonical padding, or CRC32 checks."""


class CodecEncodeError(CodecForgeError):
    """Raised when an object dictionary cannot be serialized under a CodecSpec."""


class SynthesisError(CodecForgeError):
    """Raised when synthesis fails to produce a 3-gate verified CodecSpec."""
