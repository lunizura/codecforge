from __future__ import annotations

import html
from typing import Any

from codecforge.errors import CodecDecodeError
from codecforge.oracle import OracleResult, verify_codec
from codecforge.probe import sliding_entropy
from codecforge.runtime import decode_bytes
from codecforge.schema import CodecSpec, validate_spec

_PALETTE = [
    "#38bdf8",  # sky
    "#34d399",  # emerald
    "#f472b6",  # pink
    "#fbbf24",  # amber
    "#a78bfa",  # violet
    "#fb7185",  # rose
    "#2dd4bf",  # teal
    "#f97316",  # orange
    "#818cf8",  # indigo
    "#a3e635",  # lime
]


def _format_val(val: Any) -> str:
    if isinstance(val, bytes):
        if len(val) > 24:
            return f"<{len(val)}B: {val[:16].hex()}...>"
        return val.hex()
    if isinstance(val, list):
        return f"[{len(val)} items]"
    return repr(val)


def _render_entropy_svg(data: bytes) -> str:
    points = sliding_entropy(data, window=16, step=8)
    width = 640
    height = 110
    pad_x = 12
    pad_y = 12
    plot_w = width - 2 * pad_x
    plot_h = height - 2 * pad_y

    if len(points) == 1:
        y = pad_y + plot_h * (1.0 - min(8.0, max(0.0, points[0][1])) / 8.0)
        poly = f"{pad_x:.1f},{y:.1f} {pad_x + plot_w:.1f},{y:.1f}"
    else:
        coords: list[str] = []
        denom = max(1, len(points) - 1)
        for i, (_, ent) in enumerate(points):
            x = pad_x + (i / denom) * plot_w
            y = pad_y + plot_h * (1.0 - min(8.0, max(0.0, ent)) / 8.0)
            coords.append(f"{x:.1f},{y:.1f}")
        poly = " ".join(coords)

    return (
        f'<svg viewBox="0 0 {width} {height}" class="sparkline" role="img" '
        f'aria-label="Sliding Shannon entropy sparkline">'
        f'<line x1="{pad_x}" y1="{pad_y}" x2="{pad_x + plot_w}" y2="{pad_y}" '
        f'stroke="#1e293b" stroke-dasharray="4 4" />'
        f'<line x1="{pad_x}" y1="{pad_y + plot_h / 2:.1f}" x2="{pad_x + plot_w}" '
        f'y2="{pad_y + plot_h / 2:.1f}" stroke="#1e293b" stroke-dasharray="4 4" />'
        f'<line x1="{pad_x}" y1="{pad_y + plot_h}" x2="{pad_x + plot_w}" '
        f'y2="{pad_y + plot_h}" stroke="#334155" />'
        f'<polyline fill="none" stroke="#38bdf8" stroke-width="2.5" points="{poly}" />'
        f"</svg>"
    )


def _badge(label: str, ok: bool) -> str:
    cls = "badge-pass" if ok else "badge-fail"
    status = "PASS" if ok else "FAIL"
    return f'<span class="badge {cls}">{html.escape(label)}: {status}</span>'


def generate_html_report(
    spec: CodecSpec,
    samples: list[bytes],
    oracle: OracleResult | None = None,
) -> str:
    validate_spec(spec)
    if oracle is None:
        oracle = verify_codec(spec, samples)

    field_by_name = {f.name: f for f in spec.fields}
    color_by_field = {
        f.name: _PALETTE[idx % len(_PALETTE)] for idx, f in enumerate(spec.fields)
    }

    legend_items: list[str] = []
    for f in spec.fields:
        col = color_by_field[f.name]
        desc = f.kind
        if f.scalar_type:
            desc = f"{f.kind}:{f.scalar_type}"
        legend_items.append(
            f'<div class="legend-item">'
            f'<span class="swatch" style="background:{col}"></span>'
            f'<code>{html.escape(f.name)}</code> '
            f'<span class="muted">({html.escape(desc)})</span>'
            f"</div>"
        )

    sample_sections: list[str] = []
    for s_idx, raw in enumerate(samples):
        decoded: dict[str, Any] = {}
        spans: list[tuple[str, int, int]] = []
        decode_err = ""
        try:
            decoded, spans = decode_bytes(spec, raw)
        except CodecDecodeError as exc:
            decode_err = str(exc)

        byte_meta: list[tuple[str, str, str]] = [
            ("", "#475569", "unmapped") for _ in range(len(raw))
        ]
        for fname, start, end in spans:
            col = color_by_field.get(fname, "#64748b")
            fkind = field_by_name[fname].kind if fname in field_by_name else "unknown"
            fval = _format_val(decoded.get(fname))
            tip = f"{fname} ({fkind}): {fval}"
            for pos in range(start, min(end, len(raw))):
                byte_meta[pos] = (fname, col, tip)

        hex_rows: list[str] = []
        for row_off in range(0, len(raw), 16):
            pills: list[str] = []
            ascii_chars: list[str] = []
            for j in range(16):
                pos = row_off + j
                if pos < len(raw):
                    b = raw[pos]
                    _, col, tip = byte_meta[pos]
                    pills.append(
                        f'<span class="byte-pill" style="border-bottom:2px solid {col};'
                        f'color:{col}" title="{html.escape(tip, quote=True)}">'
                        f"{b:02x}</span>"
                    )
                    ch = chr(b) if 0x20 <= b <= 0x7E else "."
                    ascii_chars.append(html.escape(ch))
                else:
                    pills.append('<span class="byte-pill empty">  </span>')
                    ascii_chars.append(" ")
            hex_rows.append(
                f'<div class="hex-row">'
                f'<span class="offset">0x{row_off:04x}</span>'
                f'<span class="bytes">{"".join(pills)}</span>'
                f'<span class="ascii">{"".join(ascii_chars)}</span>'
                f"</div>"
            )

        table_rows: list[str] = []
        for fname, start, end in spans:
            col = color_by_field.get(fname, "#64748b")
            fkind = field_by_name[fname].kind if fname in field_by_name else "unknown"
            val_str = _format_val(decoded.get(fname))
            table_rows.append(
                f"<tr>"
                f'<td><span class="swatch" style="background:{col}"></span>'
                f"<code>{html.escape(fname)}</code></td>"
                f"<td>{html.escape(fkind)}</td>"
                f"<td>0x{start:04x}..0x{end:04x} ({end - start}B)</td>"
                f"<td><code>{html.escape(val_str)}</code></td>"
                f"</tr>"
            )

        err_banner = (
            f'<div class="error-box">{html.escape(decode_err)}</div>'
            if decode_err
            else ""
        )
        sample_sections.append(
            f'<section class="card">'
            f"<h2>Sample #{s_idx} ({len(raw)} bytes)</h2>"
            f"{err_banner}"
            f'<div class="hex-dump">{"".join(hex_rows)}</div>'
            f'<table class="field-table"><thead><tr>'
            f"<th>Field</th><th>Kind</th><th>Span</th><th>Decoded Value</th>"
            f"</tr></thead><tbody>{''.join(table_rows)}</tbody></table>"
            f"</section>"
        )

    svg_sparkline = _render_entropy_svg(samples[0]) if samples else ""
    failures_html = ""
    if oracle.failures:
        items = "".join(f"<li>{html.escape(f)}</li>" for f in oracle.failures)
        failures_html = f'<section class="card error-box"><h3>Oracle Diagnostics</h3><ul>{items}</ul></section>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>CodecForge Report - {html.escape(spec.name)}</title>
<style>
  :root {{
    color-scheme: dark;
    --bg: #0b0f17;
    --panel: #111827;
    --border: #1e293b;
    --text: #e2e8f0;
    --muted: #94a3b8;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    line-height: 1.5;
  }}
  .container {{ max-width: 1120px; margin: 0 auto; display: grid; gap: 20px; }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
  }}
  h1, h2, h3 {{ margin: 0 0 12px; font-weight: 600; }}
  .meta-row {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .badge {{
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid transparent;
  }}
  .badge-pass {{ background: rgba(16, 185, 129, 0.14); color: #34d399; border-color: rgba(52, 211, 153, 0.35); }}
  .badge-fail {{ background: rgba(244, 63, 94, 0.14); color: #fb7185; border-color: rgba(251, 113, 133, 0.35); }}
  .muted {{ color: var(--muted); font-size: 13px; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 12px; }}
  .legend-item {{ display: inline-flex; align-items: center; gap: 6px; font-size: 13px; }}
  .swatch {{ display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; }}
  .sparkline {{ width: 100%; max-width: 640px; height: auto; display: block; }}
  .hex-dump {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    overflow-x: auto;
    margin-bottom: 16px;
  }}
  .hex-row {{ display: flex; gap: 12px; align-items: center; padding: 2px 0; }}
  .offset {{ color: var(--muted); min-width: 60px; }}
  .bytes {{ display: flex; gap: 4px; }}
  .byte-pill {{
    display: inline-block;
    min-width: 22px;
    text-align: center;
    padding: 1px 2px;
    border-radius: 3px;
    transition: transform 0.12s ease, background-color 0.12s ease;
    cursor: default;
  }}
  .byte-pill:hover {{ background: rgba(255, 255, 255, 0.12); transform: translateY(-1px); }}
  .byte-pill.empty {{ border: none; }}
  .ascii {{ color: var(--muted); white-space: pre; margin-left: 8px; }}
  .field-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .field-table th, .field-table td {{
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }}
  .field-table th {{ color: var(--muted); font-weight: 500; }}
  .error-box {{
    background: rgba(244, 63, 94, 0.1);
    border: 1px solid rgba(251, 113, 133, 0.35);
    color: #fecdd3;
    padding: 10px 14px;
    border-radius: 8px;
    margin-bottom: 12px;
  }}
</style>
</head>
<body>
<main class="container">
  <header class="card">
    <h1>{html.escape(spec.name)} <span class="muted">({html.escape(spec.endian)} | {len(samples)} samples)</span></h1>
    <p class="muted">{html.escape(spec.description or "CodecForge binary reverse-engineering inspection report")}</p>
    <div class="meta-row">
      {_badge("Gate 1: Bit-Exact Round-Trip", oracle.gate1_roundtrip_passed)}
      {_badge("Gate 2: Anti-Passthrough", oracle.gate2_coverage_passed)}
      {_badge("Gate 3: Mutation Fuzzer", oracle.gate3_mutation_passed)}
      <span class="muted">Opaque byte ratio: {oracle.opaque_byte_ratio:.2f}</span>
    </div>
  </header>
  {failures_html}
  <section class="card">
    <h2>Sample #0 Sliding Shannon Entropy (0..8 bits/byte)</h2>
    {svg_sparkline}
  </section>
  <section class="card">
    <h2>Field Legend</h2>
    <div class="legend">{"".join(legend_items)}</div>
  </section>
  {"".join(sample_sections)}
</main>
</body>
</html>
"""
