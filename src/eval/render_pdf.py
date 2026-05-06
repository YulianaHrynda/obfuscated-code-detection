from __future__ import annotations

from pathlib import Path

import markdown as md
from weasyprint import HTML, CSS

ROOT = Path(__file__).resolve().parents[2]
SRC_MD = ROOT / "reports" / "final_report.md"
OUT_PDF = ROOT / "reports" / "final_report.pdf"

CSS_TEXT = """
@page {
    size: A4;
    margin: 18mm 16mm 18mm 16mm;
    @bottom-right {
        content: counter(page) " / " counter(pages);
        font-family: "DejaVu Sans", sans-serif;
        font-size: 9pt;
        color: #666;
    }
}
body {
    font-family: "DejaVu Sans", "Liberation Sans", sans-serif;
    font-size: 10pt;
    line-height: 1.45;
    color: #1f2328;
}
h1 {
    font-size: 20pt;
    border-bottom: 2px solid #1f2328;
    padding-bottom: 6pt;
    margin-top: 0;
    page-break-after: avoid;
}
h2 {
    font-size: 14pt;
    margin-top: 22pt;
    border-bottom: 1px solid #d0d7de;
    padding-bottom: 3pt;
    page-break-after: avoid;
}
h3 {
    font-size: 11.5pt;
    margin-top: 16pt;
    page-break-after: avoid;
}
h4 {
    font-size: 10.5pt;
    margin-top: 12pt;
    color: #57606a;
}
p, li {
    text-align: justify;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 8pt 0 12pt 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}
th, td {
    border: 1px solid #d0d7de;
    padding: 4pt 7pt;
    text-align: left;
    vertical-align: top;
}
th {
    background-color: #f6f8fa;
    font-weight: 600;
}
td:nth-child(n+2) {
    font-variant-numeric: tabular-nums;
}
code, pre {
    font-family: "DejaVu Sans Mono", "Liberation Mono", monospace;
    background-color: #f6f8fa;
    border-radius: 3px;
}
code {
    padding: 1px 4px;
    font-size: 9pt;
}
pre {
    padding: 8pt 10pt;
    font-size: 8.5pt;
    line-height: 1.35;
    overflow-x: auto;
    border: 1px solid #e1e4e8;
    page-break-inside: avoid;
}
pre code {
    background: none;
    padding: 0;
    font-size: 8.5pt;
}
blockquote {
    border-left: 3px solid #d0d7de;
    margin: 10pt 0;
    padding: 4pt 12pt;
    color: #57606a;
    background-color: #f6f8fa;
}
hr {
    border: 0;
    border-top: 1px solid #d0d7de;
    margin: 16pt 0;
}
strong {
    color: #0a3069;
}
ul, ol {
    padding-left: 18pt;
}
"""

def main() -> None:
    text = SRC_MD.read_text(encoding="utf-8")
    body_html = md.markdown(
        text,
        extensions=["tables", "fenced_code", "sane_lists"],
    )
    full_html = (
        '<!DOCTYPE html><html lang="uk"><head>'
        '<meta charset="utf-8">'
        "<title>Obfuscated Code Detection — Final Report</title>"
        "</head><body>" + body_html + "</body></html>"
    )
    HTML(string=full_html).write_pdf(
        OUT_PDF,
        stylesheets=[CSS(string=CSS_TEXT)],
    )
    print(f"wrote PDF: {OUT_PDF}  ({OUT_PDF.stat().st_size / 1024:.1f} KB)")

if __name__ == "__main__":
    main()
