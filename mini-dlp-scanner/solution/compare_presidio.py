#!/usr/bin/env python3
"""Phase 2: compare the homemade mini DLP engine with Microsoft Presidio.

Presidio is an open-source DLP library (MIT license) that, on top of patterns,
uses a language model (NLP) to recognise people, places or organisations.
This script analyses the same text with both tools so the difference is visible.

Requires the dependencies in requirements.txt plus the Spanish spaCy model:
    pip install -r ../requirements.txt
    python -m spacy download es_core_news_sm
"""

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from mini_dlp import scan_text

# Sample text kept in Spanish on purpose: the Spanish NLP model needs it to
# recognise the person name and the city.
TEXT = (
    "El cliente Diego Fernández, de Sevilla, escribió desde diego.fdez@gmail.com "
    "porque su tarjeta 4539 1488 0343 6467 fue rechazada. Su DNI es 12345678Z y "
    "su teléfono el +34 622 998 877."
)


def build_presidio_analyzer() -> AnalyzerEngine:
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "es", "model_name": "es_core_news_sm"}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=configuration).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["es"])


def run_homemade(text: str) -> set[str]:
    return {hit["type"] for hit in scan_text(text)}


def run_presidio(analyzer: AnalyzerEngine, text: str) -> set[str]:
    results = analyzer.analyze(text=text, language="es")
    return {r.entity_type for r in results}


def main() -> None:
    print(f"Analysed text:\n  {TEXT}\n")

    homemade = run_homemade(TEXT)
    print("Homemade mini engine detects:")
    print(f"  {sorted(homemade)}\n")

    analyzer = build_presidio_analyzer()
    presidio = run_presidio(analyzer, TEXT)
    print("Microsoft Presidio detects:")
    print(f"  {sorted(presidio)}\n")

    print("Quick takeaway:")
    print("  - The homemade regex engine nails fixed-structure data")
    print("    (card, IBAN, Spanish ID) and is transparent and fast.")
    print("  - Presidio adds people and places that regex cannot see,")
    print("    because it uses a trained language model.")


if __name__ == "__main__":
    main()
