from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from codecforge import __version__
from codecforge.codegen_cpp import generate_cpp_header
from codecforge.codegen_ksy import generate_kaitai_ksy
from codecforge.codegen_py import generate_python_module
from codecforge.errors import CodecForgeError
from codecforge.oracle import verify_codec
from codecforge.probe import probe_samples
from codecforge.report_html import generate_html_report
from codecforge.schema import CodecSpec
from codecforge.synthesizer import synthesize_codec


def _load_samples(paths: Sequence[str]) -> list[bytes]:
    out: list[bytes] = []
    for p_str in paths:
        p = Path(p_str)
        if not p.is_file():
            raise CodecForgeError(f"Sample file not found: {p}")
        out.append(p.read_bytes())
    return out


def _load_spec(path_str: str) -> CodecSpec:
    p = Path(path_str)
    if not p.is_file():
        raise CodecForgeError(f"Spec file not found: {p}")
    return CodecSpec.from_yaml(p.read_text(encoding="utf-8"))


def _write_or_print(text: str, out_path: str | None) -> None:
    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _cmd_probe(args: argparse.Namespace) -> int:
    samples = _load_samples(args.samples)
    report = probe_samples(samples)
    if args.json:
        output = json.dumps(report.to_dict(), indent=2)
    else:
        output = report.to_prompt_summary(samples)
    _write_or_print(output, args.out)
    return 0


def _cmd_synthesize(args: argparse.Namespace) -> int:
    samples = _load_samples(args.samples)
    spec, oracle = synthesize_codec(
        samples,
        provider_name=args.provider,
        name=args.name,
        model=args.model,
        max_rounds=args.max_rounds,
        hint=args.hint,
    )
    yaml_text = spec.to_yaml()
    _write_or_print(yaml_text, args.out)
    if args.report:
        html_text = generate_html_report(spec, samples, oracle=oracle)
        _write_or_print(html_text, args.report)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    spec = _load_spec(args.spec)
    samples = _load_samples(args.samples)
    oracle = verify_codec(spec, samples, max_opaque_ratio=args.max_opaque_ratio)
    if args.json:
        sys.stdout.write(json.dumps(oracle.to_dict(), indent=2) + "\n")
    else:
        status = "PASS" if oracle.passed else "FAIL"
        sys.stdout.write(
            f"Oracle: {status} | Gate1={oracle.gate1_roundtrip_passed} "
            f"Gate2={oracle.gate2_coverage_passed} Gate3={oracle.gate3_mutation_passed} "
            f"opaque_ratio={oracle.opaque_byte_ratio:.2f}\n"
        )
        for failure in oracle.failures:
            sys.stderr.write(f"  - {failure}\n")
    return 0 if oracle.passed else 1


def _cmd_compile(args: argparse.Namespace) -> int:
    spec = _load_spec(args.spec)
    if args.lang == "python":
        _write_or_print(generate_python_module(spec), args.out)
    elif args.lang == "cpp":
        _write_or_print(generate_cpp_header(spec), args.out)
    elif args.lang == "ksy":
        _write_or_print(generate_kaitai_ksy(spec), args.out)
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    spec = _load_spec(args.spec)
    samples = _load_samples(args.samples)
    html_text = generate_html_report(spec, samples)
    _write_or_print(html_text, args.out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codecforge",
        description="Autonomous, round-trip-verified binary format reverse-engineering synthesizer",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser("probe", help="Align samples and detect entropy, lengths, and CRC32")
    p_probe.add_argument("samples", nargs="+", help="Paths to 2+ binary sample files")
    p_probe.add_argument("--json", action="store_true", help="Emit probe report as JSON")
    p_probe.add_argument("-o", "--out", help="Write probe output to file")
    p_probe.set_defaults(func=_cmd_probe)

    p_synth = sub.add_parser(
        "synthesize", help="Synthesize and 3-gate verify a CodecSpec YAML from samples"
    )
    p_synth.add_argument("samples", nargs="+", help="Paths to 2+ binary sample files")
    p_synth.add_argument(
        "--provider",
        choices=["heuristic", "gemini", "openai", "ollama"],
        default="heuristic",
        help="Synthesis backend (default: heuristic)",
    )
    p_synth.add_argument("--model", help="Override provider LLM model name")
    p_synth.add_argument("--name", default="synthesized_format", help="Format identifier")
    p_synth.add_argument("--hint", help="Optional domain hint passed to LLM synthesis")
    p_synth.add_argument("--max-rounds", type=int, default=4, help="Max LLM self-healing rounds")
    p_synth.add_argument("-o", "--out", help="Write synthesized CodecSpec YAML to file")
    p_synth.add_argument("--report", help="Also write dark-mode HTML inspection report")
    p_synth.set_defaults(func=_cmd_synthesize)

    p_verify = sub.add_parser("verify", help="Run the 3-Gate Anti-Cheat Oracle on a spec")
    p_verify.add_argument("spec", help="Path to CodecSpec YAML")
    p_verify.add_argument("samples", nargs="+", help="Paths to binary sample files")
    p_verify.add_argument(
        "--max-opaque-ratio",
        type=float,
        default=0.50,
        help="Maximum allowed low-entropy opaque byte ratio (default: 0.50)",
    )
    p_verify.add_argument("--json", action="store_true", help="Emit OracleResult as JSON")
    p_verify.set_defaults(func=_cmd_verify)

    p_compile = sub.add_parser("compile", help="Compile a CodecSpec YAML to Python, C++20, or .ksy")
    p_compile.add_argument("spec", help="Path to CodecSpec YAML")
    p_compile.add_argument(
        "--lang",
        choices=["python", "cpp", "ksy"],
        default="python",
        help="Target language/schema (default: python)",
    )
    p_compile.add_argument("-o", "--out", help="Output file path")
    p_compile.set_defaults(func=_cmd_compile)

    p_inspect = sub.add_parser("inspect", help="Generate dark-mode HTML byte-map report")
    p_inspect.add_argument("spec", help="Path to CodecSpec YAML")
    p_inspect.add_argument("samples", nargs="+", help="Paths to binary sample files")
    p_inspect.add_argument("-o", "--out", help="Output HTML file path")
    p_inspect.set_defaults(func=_cmd_inspect)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except (CodecForgeError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
