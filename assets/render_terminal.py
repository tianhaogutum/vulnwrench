"""Render the real `vulnwrench ci` demo output as an SVG terminal window.

Runs the offline demo in examples/ci/ under a pseudo-terminal (so ci emits its normal
ANSI colors), converts the colors to SVG, soft-wraps long lines, and writes
assets/ci-demo.svg. Nothing is edited by hand: re-run this after ci's output changes.
Uses the source tree (src/), so no install is needed.

    python3 assets/render_terminal.py            # from the repository root
    python3 assets/render_terminal.py --columns 120 --out /tmp/ci.svg
"""

from __future__ import annotations

import argparse
import os
import pty
import re
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "examples" / "ci"
ARGS = ["ci", "--trivy", "trivy.json", "--grype", "grype.json", "--osv", "osv.json", "--baseline", "baseline.json",
        "--ignores", ".trivyignore", "--ignores", "osv-scanner.toml", "--epss", "epss.csv", "--kev", "kev.json",
        "--as-of", "2026-11-12", "--reports-unfiltered"]

# Terminal palette. The window has its own dark background, so the image reads the
# same on GitHub's light and dark themes.
BG = "#14171c"
BORDER = "#3a404a"
TITLE_BAR = "#1d2128"
FG = "#d9dde3"
BRIGHT = "#ffffff"
DIM = "#8a919c"
COLORS = {31: "#ff7b72", 32: "#7ee787", 33: "#e3b341", 34: "#79c0ff", 35: "#d2a8ff", 36: "#76d4e8"}
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', 'Liberation Mono', monospace"

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def capture() -> str:
    """Run the demo under a pty and return its output with ANSI codes."""
    master, slave = pty.openpty()
    env = {**os.environ, "COLUMNS": "200",
           "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT / "src"), os.environ.get("PYTHONPATH")]))}
    env.pop("NO_COLOR", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vulnwrench", *ARGS],
        cwd=DEMO_DIR, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, env=env,
    )
    os.close(slave)
    chunks = []
    while True:
        try:
            data = os.read(master, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.close(master)
    if proc.wait() not in (0, 1):  # 1 = the gate failed, expected for the demo
        raise SystemExit(f"vulnwrench ci exited {proc.returncode}")
    return b"".join(chunks).decode("utf-8").replace("\r\n", "\n")


def parse(line: str) -> list[tuple[str, tuple]]:
    """Split one line into (text, style) runs; style = (bold, dim, color code)."""
    runs, style, pos = [], (False, False, None), 0
    for match in SGR.finditer(line):
        if match.start() > pos:
            runs.append((line[pos:match.start()], style))
        bold, dim, color = style
        for code in [int(c) for c in (match.group(1) or "0").split(";") if c]:
            if code == 0:
                bold, dim, color = False, False, None
            elif code == 1:
                bold = True
            elif code == 2:
                dim = True
            elif code == 22:
                bold = dim = False
            elif code == 39:
                color = None
            elif 30 <= code <= 37:
                color = code
        style = (bold, dim, color)
        pos = match.end()
    if pos < len(line):
        runs.append((line[pos:], style))
    return runs


def wrap(runs: list[tuple[str, tuple]], columns: int) -> list[list[tuple[str, tuple]]]:
    """Soft-wrap a styled line at spaces; continuation lines get a hanging indent."""
    text = "".join(t for t, _ in runs)
    if len(text) <= columns:
        return [runs]
    styles = [s for t, s in runs for _ in t]
    indent = len(text) - len(text.lstrip(" ")) + 4
    rows, start, first = [], 0, True
    while start < len(text):
        room = columns if first else columns - indent
        end = start + room
        if end < len(text):
            cut = text.rfind(" ", start + 1, end + 1)
            end = cut if cut > start else end
        else:
            end = len(text)
        row = [] if first else [(" " * indent, (False, False, None))]
        for i in range(start, end):
            if row and row[-1][1] == styles[i]:
                row[-1] = (row[-1][0] + text[i], styles[i])
            else:
                row.append((text[i], styles[i]))
        rows.append(row)
        start = end
        while start < len(text) and text[start] == " ":
            start += 1
        first = False
    return rows


def css_class(style: tuple) -> str:
    bold, dim, color = style
    names = []
    if bold:
        names.append("b")
    if dim and color is None:
        names.append("d")
    if color is not None:
        names.append(f"c{color}")
    return " ".join(names)


def render(output: str, columns: int) -> str:
    font_size, char_w, line_h, pad_x, pad_top, bar_h = 13, 7.83, 17, 18, 16, 32
    prompt = [("$ ", (True, False, 32)), ("vulnwrench " + " ".join(ARGS), (True, False, None))]
    lines = wrap(prompt, columns) + [row for raw in output.rstrip("\n").split("\n") for row in wrap(parse(raw), columns)]
    width = round(pad_x * 2 + columns * char_w)
    height = bar_h + pad_top + len(lines) * line_h + 10
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="t d">',
        '<title id="t">vulnwrench ci on the bundled synthetic scanner reports</title>',
        '<desc id="d">Terminal output of vulnwrench ci on examples/ci: a noise funnel from 37 raw findings '
        "from Trivy, Grype and OSV-Scanner to 2 that need action, the two exploitable findings with their "
        "follow-up commands, one finding without exploit data, three stale exceptions, the findings below the "
        "exploit threshold and the failing gate. Generated by assets/render_terminal.py.</desc>",
        "<style>"
        f"text{{font-family:{FONT};font-size:{font_size}px;fill:{FG};white-space:pre}}"
        f".b{{font-weight:700;fill:{BRIGHT}}}.d{{fill:{DIM}}}"
        + "".join(f".c{code}{{fill:{hexv}}}" for code, hexv in COLORS.items())
        + f".title{{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;fill:{DIM}}}"
        "</style>",
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" fill="{BG}" stroke="{BORDER}"/>',
        f'<path d="M0.5 {bar_h} V10.5 a10 10 0 0 1 10 -10 H{width - 10.5} a10 10 0 0 1 10 10 V{bar_h} Z" fill="{TITLE_BAR}"/>',
        f'<line x1="0.5" y1="{bar_h}" x2="{width - 0.5}" y2="{bar_h}" stroke="{BORDER}"/>',
    ]
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(f'<circle cx="{20 + i * 18}" cy="{bar_h / 2}" r="5.5" fill="{color}"/>')
    out.append(f'<text class="title" x="{width / 2}" y="{bar_h / 2 + 4}" text-anchor="middle">'
               "examples/ci  —  synthetic scanner reports, offline</text>")
    for n, row in enumerate(lines):
        y = bar_h + pad_top + n * line_h + font_size - 2
        col, spans = 0, []
        for text, style in row:
            cls = css_class(style)
            attr = f' class="{cls}"' if cls else ""
            # Anchor every space-separated chunk at its exact column so table columns
            # stay aligned whatever monospace font the viewer has.
            for chunk in re.finditer(r"\S+(?: \S+)*", text):
                x = pad_x + (col + chunk.start()) * char_w
                spans.append(f'<tspan x="{x:.1f}"{attr}>{escape(chunk.group())}</tspan>')
            col += len(text)
        if spans:
            out.append(f'<text y="{y}" xml:space="preserve">{"".join(spans)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--columns", type=int, default=120, help="wrap width in characters (default 120)")
    parser.add_argument("--out", type=Path, default=ROOT / "assets" / "ci-demo.svg")
    args = parser.parse_args()
    svg = render(capture(), args.columns)
    args.out.write_text(svg, encoding="utf-8")
    print(f"wrote {args.out} ({len(svg.encode()):,} bytes)")


if __name__ == "__main__":
    main()
