"""Render the pipeline flow diagram to SVG and PNG.

A script rather than a drawing so the picture can be corrected when the pipeline is: a diagram
maintained by hand drifts from the code within a phase, and a stale architecture picture is
worse than none because people trust it.

Run: `uv run python docs/make_flow_diagram.py`
"""

from __future__ import annotations

from pathlib import Path

W, H = 1500, 860

INK = "#1a1d21"
MUTED = "#5c6570"
RULE = "#c8cfd6"
PANEL = "#f6f8fa"

# Status colours, deliberately only three. A legend with six shades is a legend nobody reads.
DONE = ("#e6f4ea", "#1e7a45")  # built and measured
PARTIAL = ("#fff6e5", "#d98324")  # built, unproven or incomplete
TODO = ("#f1f3f5", "#8b949e")  # not started

parts: list[str] = []


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x: float, y: float, s: str, size: int = 13, fill: str = INK, weight: str = "normal",
         anchor: str = "start", mono: bool = False) -> None:
    family = "Consolas, monospace" if mono else "Segoe UI, Helvetica, Arial, sans-serif"
    parts.append(
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" fill="{fill}" '
        f'font-weight="{weight}" text-anchor="{anchor}">{esc(s)}</text>'
    )


def box(x: float, y: float, w: float, h: float, fill: str, stroke: str, width: float = 1.5) -> None:
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{width}"/>'
    )


def arrow(x1: float, y1: float, x2: float, y2: float, colour: str = MUTED, dashed: bool = False) -> None:
    dash = ' stroke-dasharray="5,4"' if dashed else ""
    parts.append(
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{colour}" stroke-width="2"{dash}/>'
    )
    # Arrowheads drawn as polygons: markers are the first thing an SVG-to-PDF converter drops.
    if x1 == x2:
        parts.append(f'<polygon points="{x2 - 5},{y2 - 8} {x2 + 5},{y2 - 8} {x2},{y2}" fill="{colour}"/>')
    else:
        parts.append(f'<polygon points="{x2 - 8},{y2 - 5} {x2 - 8},{y2 + 5} {x2},{y2}" fill="{colour}"/>')


def stage(x: float, y: float, w: float, h: float, title: str, lines: list[str],
          status: tuple[str, str], badge: str) -> None:
    fill, stroke = status
    box(x, y, w, h, fill, stroke)
    text(x + 14, y + 24, title, size=15, weight="bold")
    text(x + w - 14, y + 24, badge, size=11, fill=stroke, weight="bold", anchor="end")
    for i, line in enumerate(lines):
        text(x + 14, y + 46 + i * 17, line, size=12, fill=MUTED)


parts.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')

text(40, 44, "mistify — incident log analysis pipeline", size=24, weight="bold")
text(40, 68, "Flow and build status. Green: built and measured. Amber: built, unproven or "
             "incomplete. Grey: not started.", size=13, fill=MUTED)

# ---------------------------------------------------------------- legend
for i, (label, status) in enumerate(
    [("built + measured", DONE), ("built, unproven", PARTIAL), ("not started", TODO)]
):
    lx = 1090 + i * 0
    box(1090, 36 + i * 26, 16, 16, status[0], status[1])
    text(1114, 49 + i * 26, label, size=12, fill=MUTED)

# ---------------------------------------------------------------- ingest column
X1, WCOL = 40, 400
y = 110

stage(X1, y, WCOL, 110, "1 · Ingest", [
    "json_lines + otlp · detect floor 0.6, no overlap",
    "unrecognised -> raw_lines, recorded and warned about",
    "registered names an unknown format -> refuses",
    "elastic / loki await a live stack · bootstrapper stub",
], PARTIAL, "PHASE 1/4")
arrow(X1 + WCOL / 2, y + 110, X1 + WCOL / 2, y + 140)
y += 140

stage(X1, y, WCOL, 92, "2 · Redact", [
    "regex + entity hashing, before templating",
    "api_key, email, ipv4, ipv6, ssn · 7,282 on fixture",
    "opt-in reversible vault · mistify reveal",
], DONE, "PHASE 1")
arrow(X1 + WCOL / 2, y + 92, X1 + WCOL / 2, y + 122)
y += 122

stage(X1, y, WCOL, 110, "3 · Template", [
    "Drain3, sim_th calibrated per file",
    "over-merge detection · eviction tracked",
    "Loghub-2k grouping accuracy: mean 0.907",
    "OpenSSH 0.718 — structural, not a threshold",
], DONE, "PHASE 2")
arrow(X1 + WCOL / 2, y + 110, X1 + WCOL / 2, y + 140)
y += 140

stage(X1, y, WCOL, 110, "4 · Score anomalies", [
    "severity × burstiness × rarity — no model",
    "signal set cut at the largest score gap",
    "chronic templates flagged (>=90% of log span)",
    "no duration term in the score — Issue 8",
], PARTIAL, "PHASE 2")
arrow(X1 + WCOL / 2, y + 110, X1 + WCOL / 2, y + 140)
y += 140

stage(X1, y, WCOL, 92, "5 · Scratchpad (SQLite)", [
    "templates · log_events · notes · query_log",
    "run_metadata · adversarial_objections",
    "read-only SQL channel, authorizer-enforced",
], DONE, "PHASE 1-3")

# ---------------------------------------------------------------- investigate column
X2 = 520
y2 = 110

stage(X2, y2, WCOL, 128, "6 · Investigation loop", [
    "gemini-3.5-flash-lite · 4 tools",
    "query_templates · get_slice · run_sql · write_note",
    "read_notes · citation gate on unseen event ids",
    "history compaction >20 lines · 48k tokens/run",
    "coverage nudge: signal unexplained -> one more turn",
], DONE, "PHASE 3")
arrow(X2 + WCOL / 2, y2 + 128, X2 + WCOL / 2, y2 + 158)
y2 += 158

stage(X2, y2, WCOL, 92, "7 · Synthesis (disabled)", [
    "stronger model writes the conclusion from notes",
    "built, config default null, awaiting eval evidence",
    "cannot introduce evidence — drops uncited ids",
], TODO, "HELD")
arrow(X2 + WCOL / 2, y2 + 92, X2 + WCOL / 2, y2 + 122, dashed=True)
y2 += 122

stage(X2, y2, WCOL, 128, "8 · Adversarial pass", [
    "gemini-3.5-flash critiques · loop model rebuts",
    "objections carry ids the rebuttal quotes back",
    "caught a fabricated citation unaided",
    "3.6-flash timed out here; every request now bounded",
    "unexplained signal excludes chronic templates",
], DONE, "PHASE 3")
arrow(X2 + WCOL / 2, y2 + 128, X2 + WCOL / 2, y2 + 158)
y2 += 158

stage(X2, y2, WCOL, 110, "9 · Report", [
    "fixed Jinja · markdown, html, pdf",
    "verdict -> warnings -> at a glance -> findings",
    "-> the challenge -> templates -> appendix",
    "citations resolved to real rows before render",
], DONE, "PHASE 3/6")

# ---------------------------------------------------------------- eval column
X3 = 1000
y3 = 110

stage(X3, y3, 460, 128, "Eval harness", [
    "mistify eval --case NAME --runs N [--judge]",
    "runs through the same entry point as the CLI",
    "scores the scratchpad, never the rendered report",
    "per-check rates · JSON output · FIXTURE_VERSION",
    "731 tests · ruff + mypy clean · report kept per run",
], DONE, "PHASE 5")
y3 += 158

stage(X3, y3, 460, 110, "Cases: pool-exhaustion (+otlp)", [
    "OTLP run scored 4/4: root cause + precursor cited",
    "grep baseline leads with the herring: agent never did",
    "one report kept per run, under its own incident id",
], DONE, "4/4 OTLP")
y3 += 140

stage(X3, y3, 460, 128, "Case: quiet-hour", [
    "negative control — nothing planted",
    "3 runs: 0/3 on the confidence bar",
    "but run 3 correctly said nothing is wrong",
    "the bar cannot separate right from wrong here",
    "needs a judge question, not a threshold",
], PARTIAL, "NEEDS WORK")
y3 += 158

stage(X3, y3, 460, 92, "Templating eval", [
    "Loghub-2k · annotated ground truth · no model",
    "4 systems x 3 thresholds · mean GA 0.907",
    "first measurement on foreign logs",
], DONE, "PHASE 5")
y3 += 122

stage(X3, y3, 460, 92, "Not started", [
    "Phase 4: bootstrapper · elastic / loki need Docker",
    "Phase 5: LogDx-CI end-to-end diagnosis eval",
    "Phase 6: MCP server, packaging",
], TODO, "PHASE 4-6")

# ---------------------------------------------------------------- cross links
arrow(X1 + WCOL, 680, X2, 250)
text(X1 + WCOL + 10, 700, "tools read here", size=11, fill=MUTED)
arrow(X2 + WCOL, 174, X3, 174, dashed=True)
text(X2 + WCOL + 14, 165, "scored by", size=11, fill=MUTED)

# ---------------------------------------------------------------- footer
parts.append(f'<line x1="40" y1="{H - 56}" x2="{W - 40}" y2="{H - 56}" stroke="{RULE}" stroke-width="1"/>')
text(40, H - 32,
     "Open: Issue 8 anomaly score has no duration term · Issue 9 no token ceiling · "
     "Issue 11 quiet-hour bar conflates confident-and-right with confident-and-wrong",
     size=12, fill=MUTED)

svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
    f'viewBox="0 0 {W} {H}">' + "".join(parts) + "</svg>"
)

here = Path(__file__).parent
svg_path = here / "flow.svg"
svg_path.write_text(svg, encoding="utf-8")


def render_png(destination: Path, scale: int = 2) -> None:
    """Rasterise the same primitives with Pillow.

    Not via an SVG converter: svglib hung indefinitely on this file, and the ones that do not
    (cairosvg, weasyprint) want cairo and pango, which a stock Windows machine does not have.
    Drawing twice from one list of primitives is a little duplication in exchange for a picture
    that renders anywhere Python does.
    """
    import re

    from PIL import Image, ImageDraw, ImageFont

    def font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
        name = "consola.ttf" if mono else ("segoeuib.ttf" if bold else "segoeui.ttf")
        try:
            return ImageFont.truetype(f"C:/Windows/Fonts/{name}", size * scale)
        except OSError:  # pragma: no cover - non-Windows fallback
            return ImageFont.load_default()

    image = Image.new("RGB", (W * scale, H * scale), "#ffffff")
    draw = ImageDraw.Draw(image)

    for part in parts:
        if part.startswith("<rect"):
            a = dict(re.findall(r'([\w-]+)="([^"]*)"', part))
            # The page background is a rect with no x/y, so both default rather than raise.
            x, y = float(a.get("x", 0)) * scale, float(a.get("y", 0)) * scale
            w, h = float(a["width"]) * scale, float(a["height"]) * scale
            draw.rounded_rectangle(
                [x, y, x + w, y + h],
                radius=float(a.get("rx", 0)) * scale,
                fill=a.get("fill"),
                outline=a.get("stroke"),
                width=int(float(a.get("stroke-width", 1)) * scale),
            )
        elif part.startswith("<line"):
            a = dict(re.findall(r'([\w-]+)="([^"]*)"', part))
            draw.line(
                [
                    float(a["x1"]) * scale,
                    float(a["y1"]) * scale,
                    float(a["x2"]) * scale,
                    float(a["y2"]) * scale,
                ],
                fill=a.get("stroke"),
                width=int(float(a.get("stroke-width", 1)) * scale),
            )
        elif part.startswith("<polygon"):
            a = dict(re.findall(r'([\w-]+)="([^"]*)"', part))
            points = [
                (float(px) * scale, float(py) * scale)
                for px, py in (pair.split(",") for pair in a["points"].split())
            ]
            draw.polygon(points, fill=a.get("fill"))
        elif part.startswith("<text"):
            a = dict(re.findall(r'([\w-]+)="([^"]*)"', part))
            body = re.sub(r"<[^>]+>", "", part)
            body = body.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            size = int(float(a.get("font-size", 13)))
            bold = a.get("font-weight") == "bold"
            mono = "Consolas" in a.get("font-family", "")
            typeface = font(size, bold=bold, mono=mono)
            x, y = float(a["x"]) * scale, float(a["y"]) * scale
            anchor = "rs" if a.get("text-anchor") == "end" else "ls"
            draw.text((x, y), body, font=typeface, fill=a.get("fill", INK), anchor=anchor)

    image.save(destination)


png_path = here / "flow.png"
render_png(png_path)
print(f"wrote {svg_path} and {png_path}")
