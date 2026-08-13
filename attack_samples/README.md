# Inert attack fixtures

These files contain non-executed prompt-injection and document-structure test
patterns. Do not open them in production office applications. Regenerate them
with `scripts/generate_attack_corpus.py attack_samples`.

The corpus covers visible instructions, CSS-hidden HTML, active Markdown links,
hidden DOCX runs, hidden XLSX rows, off-canvas PPTX shapes, PDF JavaScript,
tiny PDF text, and transparent PNG metadata.
