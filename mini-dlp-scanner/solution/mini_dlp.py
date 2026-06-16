#!/usr/bin/env python3
"""Mini DLP engine: scans files looking for sensitive data (PII).

Reference solution for the "Build your own mini DLP engine" exercise.
Uses only the Python standard library, so there is nothing to install.

It detects credit cards, IBANs, Spanish national IDs (DNI/NIE), emails,
Spanish phone numbers and API tokens. For data that carries a mathematical
checksum (card, IBAN, DNI) it does not trust the shape of the text alone: it
validates every candidate with its control algorithm to drop false positives.

Usage:
    python mini_dlp.py --path ../sample-data
    python mini_dlp.py --path ../sample-data --format both --output report
"""

import argparse
import csv
import json
import re
from pathlib import Path


def is_valid_luhn(number: str) -> bool:
    """Luhn checksum. Real credit card numbers satisfy it."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
NIE_PREFIX = {"X": "0", "Y": "1", "Z": "2"}


def is_valid_dni(value: str) -> bool:
    """Validate the control letter of a Spanish DNI/NIE (modulo 23)."""
    text = value.upper().replace("-", "").replace(" ", "")
    if len(text) < 9:
        return False
    if text[0] in NIE_PREFIX:                 # NIE: X/Y/Z -> 0/1/2
        number = NIE_PREFIX[text[0]] + text[1:8]
        letter = text[8]
    else:                                     # DNI: 8 digits + letter
        number = text[:8]
        letter = text[8]
    if not number.isdigit() or not letter.isalpha():
        return False
    return DNI_LETTERS[int(number) % 23] == letter


def is_valid_iban(value: str) -> bool:
    """Validate an IBAN with the mod-97 algorithm (ISO 13616)."""
    iban = value.upper().replace(" ", "")
    if len(iban) < 15 or not iban[:2].isalpha():
        return False
    rearranged = iban[4:] + iban[:4]          # move country + check digits to the end
    converted = ""
    for char in rearranged:
        if char.isdigit():
            converted += char
        elif char.isalpha():
            converted += str(ord(char) - 55)  # A=10, B=11, ... Z=35
        else:
            return False
    return int(converted) % 97 == 1


DETECTORS = [
    {
        "type": "CREDIT_CARD",
        "label": "Credit card",
        "regex": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "validator": is_valid_luhn,
        "sensitivity": "HIGH",
    },
    {
        "type": "IBAN",
        "label": "Bank account (IBAN)",
        "regex": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?\d){10,30}\b"),
        "validator": is_valid_iban,
        "sensitivity": "HIGH",
    },
    {
        "type": "DNI_NIE",
        "label": "Spanish national ID (DNI/NIE)",
        "regex": re.compile(r"\b[XYZ]?\d{7,8}[- ]?[A-Za-z]\b"),
        "validator": is_valid_dni,
        "sensitivity": "HIGH",
    },
    {
        "type": "API_TOKEN",
        "label": "API token / key",
        "regex": re.compile(r"\b(?:sk|pk|ghp|xoxb)[-_][A-Za-z0-9_-]{8,}\b"),
        "validator": None,
        "sensitivity": "HIGH",
    },
    {
        "type": "EMAIL",
        "label": "Email address",
        "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "validator": None,
        "sensitivity": "MEDIUM",
    },
    {
        "type": "PHONE_ES",
        "label": "Spanish phone number",
        "regex": re.compile(r"(?<!\d)(?:\+34[ ]?)?[6789]\d{2}[ ]?\d{3}[ ]?\d{3}(?!\d)"),
        "validator": None,
        "sensitivity": "MEDIUM",
    },
]


def scan_text(text: str) -> list[dict]:
    """Return the findings of a text, with overlaps removed."""
    candidates = []
    for detector in DETECTORS:
        for match in detector["regex"].finditer(text):
            value = match.group()
            validator = detector["validator"]
            if validator is not None and not validator(value):
                continue                      # looked like PII but failed validation: skip it
            candidates.append({
                "type": detector["type"],
                "label": detector["label"],
                "value": value,
                "sensitivity": detector["sensitivity"],
                "start": match.start(),
                "end": match.end(),
            })

    # When two detectors match the same span, keep the longest one.
    candidates.sort(key=lambda c: (c["start"], -(c["end"] - c["start"])))
    findings = []
    last_end = -1
    for candidate in candidates:
        if candidate["start"] >= last_end:
            findings.append(candidate)
            last_end = candidate["end"]
    return findings


def redact_value(value: str) -> str:
    """Mask a value keeping the first 2 and last 2 alphanumeric characters.
    Spaces and dashes are preserved."""
    chars = list(value)
    alnum = [i for i, c in enumerate(chars) if c.isalnum()]
    if len(alnum) > 4:
        for i in alnum[2:-2]:
            chars[i] = "*"
    else:
        for i in alnum:
            chars[i] = "*"
    return "".join(chars)


def line_of(text: str, position: int) -> int:
    """Line number (starting at 1) for a position in the text."""
    return text.count("\n", 0, position) + 1


def scan_path(root: Path) -> list[dict]:
    """Scan a single file or, recursively, every file in a folder."""
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    findings = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        for hit in scan_text(text):
            findings.append({
                "file": str(file),
                "line": line_of(text, hit["start"]),
                "type": hit["type"],
                "label": hit["label"],
                "sensitivity": hit["sensitivity"],
                "masked_value": redact_value(hit["value"]),
            })
    return findings


def summarize(findings: list[dict]) -> dict:
    """Count findings by type and by sensitivity level."""
    by_type: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        by_level[f["sensitivity"]] = by_level.get(f["sensitivity"], 0) + 1
    return {"total": len(findings), "by_type": by_type, "by_level": by_level}


def write_json(findings: list[dict], summary: dict, path: Path) -> None:
    data = {"summary": summary, "findings": findings}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(findings: list[dict], path: Path) -> None:
    columns = ["file", "line", "type", "label", "sensitivity", "masked_value"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(findings)


def print_summary(summary: dict) -> None:
    print(f"\n  Total findings: {summary['total']}")
    print("  By sensitivity level:")
    for level in ("HIGH", "MEDIUM", "LOW"):
        if level in summary["by_level"]:
            print(f"    - {level}: {summary['by_level'][level]}")
    print("  By data type:")
    for data_type, count in sorted(summary["by_type"].items()):
        print(f"    - {data_type}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Example mini DLP engine.")
    parser.add_argument("--path", default="../sample-data",
                        help="File or folder to scan.")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="json",
                        help="Report format to generate.")
    parser.add_argument("--output", default="report",
                        help="Base name for the report files.")
    args = parser.parse_args()

    root = Path(args.path)
    if not root.exists():
        parser.error(f"Path '{root}' does not exist.")

    findings = scan_path(root)
    summary = summarize(findings)

    if args.format in ("json", "both"):
        write_json(findings, summary, Path(f"{args.output}.json"))
        print(f"  JSON report written to {args.output}.json")
    if args.format in ("csv", "both"):
        write_csv(findings, Path(f"{args.output}.csv"))
        print(f"  CSV report written to {args.output}.csv")

    print_summary(summary)


if __name__ == "__main__":
    main()
