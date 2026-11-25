from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from codecforge.cli import main
from tests.fixtures import make_rpg_save_samples, make_simple_save_samples


def _write_samples(tmp_path: Path, samples: list[bytes]) -> list[str]:
    paths: list[str] = []
    for idx, data in enumerate(samples):
        p = tmp_path / f"sample_{idx}.bin"
        p.write_bytes(data)
        paths.append(str(p))
    return paths


def test_cli_probe_json_and_text(tmp_path: Path, capsys) -> None:
    samples, _ = make_simple_save_samples()
    sample_paths = _write_samples(tmp_path, samples)

    rc = main(["probe", *sample_paths, "--json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["sample_count"] == 3
    assert len(data["checksum_candidates"]) == 1

    out_txt = tmp_path / "probe.txt"
    rc2 = main(["probe", *sample_paths, "-o", str(out_txt)])
    assert rc2 == 0
    assert "SAV1" in out_txt.read_text(encoding="utf-8")


def test_cli_synthesize_verify_compile_inspect_flow(tmp_path: Path) -> None:
    samples, _ = make_simple_save_samples()
    sample_paths = _write_samples(tmp_path, samples)

    spec_path = tmp_path / "simple_save.yaml"
    report_path = tmp_path / "synth_report.html"
    rc = main([
        "synthesize",
        *sample_paths,
        "--provider",
        "heuristic",
        "--name",
        "simple_save",
        "-o",
        str(spec_path),
        "--report",
        str(report_path),
    ])
    assert rc == 0
    assert spec_path.is_file()
    assert "<!DOCTYPE html>" in report_path.read_text(encoding="utf-8")

    # verify
    rc_v = main(["verify", "--spec", str(spec_path), *sample_paths])
    assert rc_v == 0

    # compile all targets
    out_dir = tmp_path / "compiled"
    rc_c = main(["compile", "--spec", str(spec_path), "--target", "all", "-o", str(out_dir)])
    assert rc_c == 0
    assert (out_dir / "simple_save.py").is_file()
    assert (out_dir / "simple_save.hpp").is_file()
    assert (out_dir / "simple_save.ksy").is_file()

    ksy_data = yaml.safe_load((out_dir / "simple_save.ksy").read_text(encoding="utf-8"))
    assert ksy_data["meta"]["id"] == "simple_save"

    # inspect
    inspect_html = tmp_path / "inspect.html"
    rc_i = main(["inspect", "--spec", str(spec_path), *sample_paths, "-o", str(inspect_html)])
    assert rc_i == 0
    assert "Gate 1: Bit-Exact Round-Trip: PASS" in inspect_html.read_text(encoding="utf-8")


def test_cli_failure_exit_codes(tmp_path: Path) -> None:
    samples, spec = make_rpg_save_samples()
    sample_paths = _write_samples(tmp_path, samples)

    # Missing file
    assert main(["probe", str(tmp_path / "missing1.bin"), str(tmp_path / "missing2.bin")]) == 1

    # Verify failing spec returns 1
    bad_spec_path = tmp_path / "bad.yaml"
    bad_spec_path.write_text(
        "name: bad\nendian: le\nfields:\n  - name: blob\n    kind: bytes_rest\n",
        encoding="utf-8",
    )
    assert main(["verify", "--spec", str(bad_spec_path), *sample_paths]) == 1

    # Only 1 sample to probe returns 1
    assert main(["probe", sample_paths[0]]) == 1

    # Compile invalid YAML returns 1
    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text(":::bad_yaml:::", encoding="utf-8")
    assert main(["compile", "--spec", str(invalid_yaml), "--target", "py"]) == 1


def test_cli_entrypoint_subprocess_and_demo_script(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "codecforge.cli", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "0.1.0" in proc.stdout

    demo_script = Path(__file__).resolve().parent.parent / "examples" / "generate_demo_samples.py"
    proc_demo = subprocess.run(
        [sys.executable, str(demo_script)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc_demo.returncode == 0
