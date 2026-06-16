import re
from pathlib import Path
text = "Escríbeme a ana.garcia@innova.es cuando puedas."
pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
print(pattern.findall(text))

def is_valid_luhn(number: str) -> bool:
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

print(is_valid_luhn("4539 1488 0343 6467")) # real test card -> True
print(is_valid_luhn("1234 5678 9012 3456")) # order number -> False

DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
NIE_PREFIX = {"X": "0", "Y": "1", "Z": "2"}
def is_valid_dni(value: str) -> bool:
    text = value.upper().replace("-", "").replace(" ", "")
    if len(text) < 9:
        return False
    if text[0] in NIE_PREFIX:
        number = NIE_PREFIX[text[0]] + text[1:8]
        letter = text[8]
    else:
        number = text[:8]
        letter = text[8]
    if not number.isdigit() or not letter.isalpha():
        return False
    return DNI_LETTERS[int(number) % 23] == letter

print(is_valid_dni("12345678X"))

def is_valid_iban(value: str) -> bool:
    iban = value.upper().replace(" ", "")
    if len(iban) < 15 or not iban[:2].isalpha():
        return False
    rearranged = iban[4:] + iban[:4]
    converted = ""
    for char in rearranged:
        if char.isdigit():
            converted += char
        elif char.isalpha():
            converted += str(ord(char) - 55)
        else:
            return False
    return int(converted) % 97 == 1

print(is_valid_iban("ES59 0128 7962 1757 5889 1333"))

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
    candidates = []
    for detector in DETECTORS:
        for match in detector["regex"].finditer(text):
            value = match.group()
            validator = detector["validator"]
            if validator is not None and not validator(value):
                continue
            candidates.append({
                "type": detector["type"],
                "label": detector["label"],
                "value": value,
                "sensitivity": detector["sensitivity"],
                "start": match.start(),
                "end": match.end(),
            })
    candidates.sort(key=lambda c: (c["start"], -(c["end"] - c["start"])))
    findings = []
    last_end = -1
    for candidate in candidates:
        if candidate["start"] >= last_end:
            findings.append(candidate)
            last_end = candidate["end"]
    return findings

def redact_value(value: str) -> str:
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
    return text.count("\n", 0, position) + 1

def scan_path(root: Path) -> list[dict]:
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

import csv
import json

def summarize(findings: list[dict]) -> dict:
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

import argparse

def main() -> None:
    parser = argparse.ArgumentParser(description="Example mini DLP engine.")
    parser.add_argument("--path", default="../sample-data")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="json")
    parser.add_argument("--output", default="report")
    args = parser.parse_args()

    root = Path(args.path)
    if not root.exists():
        parser.error(f"Path '{root}' does not exist.")

    findings = scan_path(root)
    summary = summarize(findings)

    if args.format in ("json", "both"):
        write_json(findings, summary, Path(f"{args.output}.json"))
        print(f" JSON report written to {args.output}.json")
    if args.format in ("csv", "both"):
        write_csv(findings, Path(f"{args.output}.csv"))
        print(f" CSV report written to {args.output}.csv")

    print(f"\n Total findings: {summary['total']}")
    print(f" By level: {summary['by_level']}")
    print(f" By type: {summary['by_type']}")


if __name__ == "__main__":
    main()