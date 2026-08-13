from pathlib import Path

from injection_firewall.contract import RiskLevel
from injection_firewall.engine import scan_file

CORPUS = Path(__file__).parents[2] / "attack_samples"


def test_structural_attack_corpus_never_returns_low() -> None:
    for name in (
        "visible-instruction.txt",
        "hidden-css.html",
        "active-link.md",
        "hidden-run.docx",
        "hidden-row.xlsx",
        "off-canvas.pptx",
        "javascript.pdf",
        "tiny-text.pdf",
        "transparent-metadata.png",
    ):
        artifacts = scan_file(CORPUS / name)
        assert artifacts.result.risk_level is not RiskLevel.LOW, name
        assert artifacts.derivative_text is None, name
