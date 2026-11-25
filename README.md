# codecforge

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab)
![License: MIT](https://img.shields.io/badge/license-MIT-10b981)
![C++20](https://img.shields.io/badge/codegen-C%2B%2B20%20%7C%20Python%20%7C%20Kaitai-38bdf8)
![Zero SDK Deps](https://img.shields.io/badge/runtime-stdlib%20%2B%20pyyaml-a78bfa)

**codecforge** is an autonomous, round-trip-verified binary format reverse-engineering synthesizer, code generator, and visual byte-map inspector.

Given 2 or more binary sample files of an unknown format, `codecforge` aligns invariant vs. variable/shifted byte regions, detects magic headers, length prefixes, and CRC32 trailers, synthesizes a declarative bidirectional format specification (`CodecSpec`), verifies it against a **3-Gate Anti-Cheat Oracle**, and compiles standalone Python modules, single-header `#pragma once` C++20 codecs, Kaitai Struct (`.ksy`) schemas, and standalone dark-mode HTML hex-map reports.

---

## Architecture

```text
  2+ Binary Samples
         |
         v
  [ probe.py ]  -----> Shannon entropy, monotonic SequenceMatcher alignment,
         |             length-prefix & trailer CRC32 detectors
         v
  [ synthesizer.py ] -> Offline Heuristic (--provider heuristic)
         |              OR BYOK LLM Self-Healing Loop (gemini | openai | ollama)
         v
  [ oracle.py ]  ----> 3-Gate Anti-Cheat Verification
         |              1. Bit-exact encode(decode(sample)) == sample
         |              2. Anti-passthrough & header magic coverage guard
         |              3. Semantic mutation fuzzing (length_of / count_of / crc32_of)
         v
  [ codegen_* / report_html ]
         ├── Python 3.10+ standalone module (zero external imports)
         ├── C++20 single-header #pragma once codec + inline ISO-3309 CRC32
         ├── Kaitai Struct (.ksy) YAML schema
         └── Dark-mode HTML5 byte-map & entropy sparkline report
```

---

## The 3-Gate Anti-Cheat Oracle

Synthesizing a schema that merely "parses" samples is easy to game (e.g., dumping the whole file into `bytes_rest` or hardcoding derived length/CRC fields). Every `CodecSpec` must pass all three gates:

1. **Gate 1 — Bit-Exact Round-Trip:** Every sample must decode cleanly via the 3-pass runtime and re-encode byte-for-byte identically (`encode_obj(spec, decode_bytes(spec, sample)) == sample`).
2. **Gate 2 — Anti-Passthrough Guard:** On non-high-entropy inputs (`entropy < 7.0`), rejects single-field `bytes_rest`/`fixed_bytes` blobs, caps low-entropy opaque byte coverage (`<= 0.50`), and requires a `magic` field when samples share a printable ASCII header prefix.
3. **Gate 3 — Semantic Mutation Fuzzing:** Mutates every non-derived field (growing `var_str` by +3 bytes, `cstr` by +2 bytes, `array` by +2 items, incrementing scalars) without updating derived `length_of`, `count_of`, or `crc32_of` fields, then verifies `encode -> decode -> encode` remains bit-exact and all mutated values survive round-trip. Any omitted `length_of`, `count_of`, or `crc32_of` relation fails immediately.

---

## Quickstart

Install from source:

```bash
pip install -e ".[dev]"
```

Generate the 3 deterministic demo binary samples and run the full pipeline:

```bash
python examples/generate_demo_samples.py

# 1. Probe alignment, length prefixes, and CRC32 trailers
codecforge probe examples/samples/save_slot1.sav examples/samples/save_slot2.sav examples/samples/save_slot3.sav

# 2. Synthesize & 3-gate verify a CodecSpec offline
codecforge synthesize examples/samples/save_slot1.sav examples/samples/save_slot2.sav examples/samples/save_slot3.sav --provider heuristic --name simple_save -o simple_save.yaml

# 3. Verify an existing spec against samples
codecforge verify simple_save.yaml examples/samples/save_slot1.sav examples/samples/save_slot2.sav examples/samples/save_slot3.sav

# 4. Compile standalone Python, C++20, and Kaitai Struct codecs
codecforge compile simple_save.yaml --lang python -o simple_save.py
codecforge compile simple_save.yaml --lang cpp -o simple_save.hpp
codecforge compile simple_save.yaml --lang ksy -o simple_save.ksy

# 5. Generate a standalone dark-mode HTML hex-map inspection report
codecforge inspect simple_save.yaml examples/samples/save_slot1.sav examples/samples/save_slot2.sav -o report.html
```

---

## BYOK LLM Providers (Zero-SDK `urllib`)

For complex formats with nested arrays or multi-field records, use `--provider`:

- **Gemini Interactions API (`--provider gemini`, default `gemini-4-hydrogen`):**
  ```bash
  export GEMINI_API_KEY="your-key"
  codecforge synthesize samples/*.bin --provider gemini -o spec.yaml
  ```
- **OpenAI (`--provider openai`, default `gpt-4o-mini`):**
  ```bash
  export OPENAI_API_KEY="your-key"
  codecforge synthesize samples/*.bin --provider openai -o spec.yaml
  ```
- **Local Ollama (`--provider ollama`, default `qwen2.5-coder:7b`):**
  ```bash
  codecforge synthesize samples/*.bin --provider ollama -o spec.yaml
  ```

---

## Generated Code Examples

### Standalone Python

```python
import simple_save  # zero external dependencies

with open("examples/samples/save_slot1.sav", "rb") as f:
    obj = simple_save.decode(f.read())

obj["text_4"] = "UpdatedHeroName"
repacked = simple_save.encode(obj)  # automatically recomputes length_of & crc32_of
```

### Single-Header C++20

```cpp
#include "simple_save.hpp"
#include <vector>

std::vector<std::uint8_t> raw = /* read file bytes */;
auto obj = codecforge_gen::SimpleSave::decode(raw);
obj.text_4 = "UpdatedHeroName";
auto repacked = codecforge_gen::SimpleSave::encode(obj); // UB-free endian & CRC32
```
