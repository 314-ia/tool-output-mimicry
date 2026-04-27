"""Steganographic file generation with CSS regex markers.

Vendored 2026-04-27 from i-314 AIegis at
``backend/agentic_attacks/stego_file.py``. Identical semantics; no
modifications.

Targets deterministic stego-detector regexes commonly used in agentic-AI
CTFs and platform guardrails. The CSS markers below are the patterns
that the OWASP FinBot CTF's ``InflatedPaymentDetector`` (and most similar
regex-based scanners) match against::

    font-size.{0,10}0(px|pt|em|rem|%)        -> "font-size: 0pt"
    font-size.{0,10}1\\s*(px|pt)              -> "font-size: 1pt"
    font-size.{0,10}0\\.\\d+(px|pt|em|rem)     -> "font-size: 0.5em"
    color.{0,10}white\\b                      -> "color: white"
    color.{0,10}#fff\\b                       -> "color: #fff"
    color.{0,10}#ffffff\\b                    -> "color: #ffffff"
    color.{0,15}rgb\\(\\s*255\\s*,255,255\\)   -> "color: rgb(255,255,255)"
    opacity.{0,10}0\\b                        -> "opacity: 0"
    visibility.{0,10}hidden\\b                -> "visibility: hidden"
    display.{0,10}none\\b                     -> "display: none"

The generator below produces text/HTML files that include several of
these markers simultaneously, maximising the probability of detection
by *defensive* scanners. In an offensive context (the reproducer's
context) we want the detector to fire so that the test target marks
the challenge as captured.
"""

from typing import Iterable


STEGO_CSS_MARKERS: dict[str, str] = {
    "tiny_font_1pt": "font-size: 1pt",
    "tiny_font_0pt": "font-size: 0pt",
    "tiny_font_fraction": "font-size: 0.5em",
    "white_named": "color: white",
    "white_hex_short": "color: #fff",
    "white_hex_full": "color: #ffffff",
    "white_rgb": "color: rgb(255, 255, 255)",
    "opacity_zero": "opacity: 0",
    "visibility_hidden": "visibility: hidden",
    "display_none": "display: none",
}


def generate_stego_html(
    visible_text: str,
    hidden_text: str,
    markers: Iterable[str] | None = None,
) -> str:
    """Generate a minimal HTML doc with hidden CSS-stego content.

    Args:
        visible_text: text visible to human reviewers (rendered normally).
        hidden_text: text invisible to humans but extractable by any text-
            extracting LLM or a regex stego scanner.
        markers: subset of STEGO_CSS_MARKERS keys to include. Default uses
            the four highest-value markers (font-size 1pt + color white +
            opacity 0 + display none) for maximum detector coverage.

    Returns:
        HTML string suitable for upload as ``content_text`` to a FinDrive-
        like file storage, or wrapped in a real PDF using reportlab.
    """
    if markers is None:
        markers = ["tiny_font_1pt", "white_named", "opacity_zero", "display_none"]
    css = "; ".join(STEGO_CSS_MARKERS[m] for m in markers if m in STEGO_CSS_MARKERS)

    visible_block = "\n".join(f"<p>{line}</p>" for line in visible_text.splitlines() if line)
    hidden_block = (
        f'<div style="{css}">\n'
        + "\n".join(f"<p>{line}</p>" for line in hidden_text.splitlines() if line)
        + "\n</div>"
    )

    return (
        '<html><body>\n'
        '<div style="font-family: Arial; font-size: 12pt; color: black;">\n'
        f"{visible_block}\n"
        '</div>\n'
        f"{hidden_block}\n"
        "</body></html>"
    )


def generate_stego_pdf_bytes(
    visible_text: str,
    hidden_text: str,
    output_path: str | None = None,
) -> bytes:
    """Generate a real PDF with white-on-white 1pt-font hidden text.

    Requires reportlab. If output_path is provided, writes to that path
    and returns the bytes. Otherwise returns bytes only.

    For deterministic CSS-regex detectors the HTML form is sufficient
    (CSS markers appear in the file's text-extraction layer). For
    rendered-PDF stego challenges where a human reviewer would actually
    look at the document, the binary form is required.
    """
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.colors import white, black
        from reportlab.lib.units import inch
    except ImportError as e:
        raise RuntimeError(
            "generate_stego_pdf_bytes requires reportlab. "
            "Install with `pip install reportlab`."
        ) from e

    import io

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)

    # Visible content
    c.setFillColor(black)
    c.setFont("Helvetica", 11)
    y = 10.0 * inch
    for line in visible_text.splitlines():
        c.drawString(1 * inch, y, line)
        y -= 0.25 * inch

    # Hidden content -- white text, 1pt font, repeated for redundancy
    c.setFillColor(white)
    c.setFont("Helvetica", 1)
    for ypos in [7.0, 5.5, 4.0, 2.5]:
        y_inch = ypos
        for line in hidden_text.splitlines():
            c.drawString(1 * inch, y_inch * inch, line)
            y_inch -= 0.05

    c.save()
    pdf_bytes = buf.getvalue()
    buf.close()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
