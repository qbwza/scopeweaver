#!/usr/bin/env python3
"""
Lightweight source triage for authorized Solana/Anchor security review.

This script intentionally reports *review signals*, not vulnerabilities.
It has no third-party Python dependencies and does not access the network.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

SKIP_DIRS = {
    ".git", "target", "node_modules", ".anchor", "dist",
    "build", "vendor", ".venv", "venv",
}

SOURCE_EXTS = {".rs", ".toml"}

PATTERNS = {
    "raw_account_info": re.compile(r"\bAccountInfo\s*<"),
    "unchecked_account": re.compile(r"\bUncheckedAccount\s*<"),
    "remaining_accounts": re.compile(r"\bremaining_accounts\b"),
    "invoke": re.compile(r"(?<!_)\binvoke\s*\("),
    "invoke_signed": re.compile(r"\binvoke_signed\s*\("),
    "create_program_address": re.compile(r"\bcreate_program_address\s*\("),
    "find_program_address": re.compile(r"\bfind_program_address\s*\("),
    "pda_seeds": re.compile(r"\bseeds\s*="),
    "pda_bump": re.compile(r"\bbump\b"),
    "has_one_constraint": re.compile(r"\bhas_one\s*="),
    "owner_constraint": re.compile(r"\bowner\s*="),
    "address_constraint": re.compile(r"\baddress\s*="),
    "signer_type": re.compile(r"\bSigner\s*<"),
    "token_account": re.compile(r"\bTokenAccount\b"),
    "interface_account": re.compile(r"\bInterfaceAccount\s*<"),
    "token_interface": re.compile(r"\bTokenInterface\b|\btoken_interface\b"),
    "token_2022": re.compile(r"\bspl_token_2022\b|\bToken2022\b|\bTOKEN_2022_PROGRAM_ID\b"),
    "transfer_checked": re.compile(r"\btransfer_checked\b"),
    "token_transfer": re.compile(r"\btransfer\s*\("),
    "oracle": re.compile(r"\boracle\b|\bpyth\b|\bswitchboard\b", re.IGNORECASE),
    "stale": re.compile(r"\bstale\b|\bstaleness\b", re.IGNORECASE),
    "confidence": re.compile(r"\bconfidence\b|\bconf\b", re.IGNORECASE),
    "load_mut": re.compile(r"\bload_mut\s*\("),
    "unsafe": re.compile(r"\bunsafe\b"),
    "unwrap": re.compile(r"\.unwrap\s*\("),
    "expect": re.compile(r"\.expect\s*\("),
    "checked_math": re.compile(r"\bchecked_(?:add|sub|mul|div|pow|rem)\b"),
    "saturating_math": re.compile(r"\bsaturating_(?:add|sub|mul|pow)\b"),
    "declare_id": re.compile(r'declare_id!\s*\(\s*"([^"]+)"\s*\)'),
}

SIGNAL_LIMIT = 12


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix in SOURCE_EXTS or root.name == "Anchor.toml":
            yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in SOURCE_EXTS or path.name == "Anchor.toml":
            yield path


def relpath(path: Path, root: Path) -> str:
    try:
        if root.is_file():
            return path.name
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_file(path: Path, root: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {}, [], {"file": relpath(path, root), "error": str(exc)}

    counts = defaultdict(int)
    examples = defaultdict(list)
    declared_ids = []

    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS.items():
            matches = list(pattern.finditer(line))
            if not matches:
                continue

            counts[name] += len(matches)
            if len(examples[name]) < SIGNAL_LIMIT:
                examples[name].append({
                    "file": relpath(path, root),
                    "line": lineno,
                    "text": line.strip()[:240],
                })

            if name == "declare_id":
                for match in matches:
                    declared_ids.append({
                        "program_id": match.group(1),
                        "file": relpath(path, root),
                        "line": lineno,
                    })

    return dict(counts), declared_ids, dict(examples)


def merge_counts(total: Dict[str, int], incoming: Dict[str, int]) -> None:
    for key, value in incoming.items():
        total[key] = total.get(key, 0) + value


def merge_examples(total: Dict[str, List[dict]], incoming: Dict[str, List[dict]]) -> None:
    for key, values in incoming.items():
        remaining = SIGNAL_LIMIT - len(total.setdefault(key, []))
        if remaining > 0:
            total[key].extend(values[:remaining])


def parse_anchor_programs(root: Path) -> List[dict]:
    anchor = root / "Anchor.toml" if root.is_dir() else None
    if not anchor or not anchor.exists():
        return []

    programs = []
    section = None
    section_re = re.compile(r"^\s*\[programs\.([^\]]+)\]\s*$")
    kv_re = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"\s*$')

    try:
        lines = anchor.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    for lineno, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        sm = section_re.match(line)
        if sm:
            section = sm.group(1)
            continue
        if section:
            km = kv_re.match(line)
            if km:
                programs.append({
                    "cluster": section,
                    "name": km.group(1),
                    "program_id": km.group(2),
                    "line": lineno,
                })
    return programs


def inspect_toolchain(root: Path) -> dict:
    result = {}
    anchor = root / "Anchor.toml" if root.is_dir() else None
    cargo = root / "Cargo.toml" if root.is_dir() else None

    if anchor and anchor.exists():
        text = anchor.read_text(encoding="utf-8", errors="replace")
        for key in ("anchor_version", "solana_version"):
            m = re.search(rf'^\s*{key}\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if m:
                result[key] = m.group(1)

    if cargo and cargo.exists():
        text = cargo.read_text(encoding="utf-8", errors="replace")
        for dep in ("anchor-lang", "anchor-spl", "solana-program", "spl-token", "spl-token-2022"):
            m = re.search(
                rf'^\s*{re.escape(dep)}\s*=\s*(?:"([^"]+)"|\{{[^\n]*version\s*=\s*"([^"]+)")',
                text,
                re.MULTILINE,
            )
            if m:
                result[dep] = m.group(1) or m.group(2)

    return result


def derive_review_signals(counts: Dict[str, int], anchor_programs: List[dict]) -> List[dict]:
    signals = []

    def add(signal: str, reason: str, priority: str = "medium"):
        signals.append({"priority": priority, "signal": signal, "reason": reason})

    if counts.get("remaining_accounts", 0):
        add(
            "remaining_accounts present",
            "Manually validate account identity, owner, signer/writable status, mint/authority binding, and any CPI forwarding.",
            "high",
        )

    if counts.get("unchecked_account", 0):
        add(
            "UncheckedAccount present",
            "Confirm each unchecked account has explicit semantic validation before use.",
            "high",
        )

    if counts.get("raw_account_info", 0):
        add(
            "Raw AccountInfo usage",
            "Review owner/type/signer/writable checks and hand-written deserialization.",
            "medium",
        )

    if counts.get("invoke_signed", 0):
        add(
            "invoke_signed usage",
            "Map signer seeds and determine the full authority granted to the PDA across all CPI targets.",
            "high",
        )

    if counts.get("create_program_address", 0):
        add(
            "Manual create_program_address",
            "Review canonical bump handling, user-controlled bumps, and legacy/new PDA namespace collisions.",
            "high",
        )

    if counts.get("token_account", 0) and not (
        counts.get("token_interface", 0) or counts.get("token_2022", 0)
    ):
        add(
            "Classic SPL Token-oriented code",
            "If arbitrary or permissionless mints are accepted, validate assumptions against Token-2022 extensions and actual balance deltas.",
            "medium",
        )

    if counts.get("oracle", 0) and not counts.get("stale", 0):
        add(
            "Oracle references without obvious staleness keyword",
            "Manually verify freshness/slot-age checks; keyword absence is not proof of missing validation.",
            "high",
        )

    if counts.get("oracle", 0) and not counts.get("confidence", 0):
        add(
            "Oracle references without obvious confidence keyword",
            "Check whether confidence/status bounds are handled elsewhere or omitted.",
            "medium",
        )

    if counts.get("unsafe", 0):
        add(
            "unsafe Rust present",
            "Review memory/layout assumptions and whether unsafe code touches account data or arithmetic-critical paths.",
            "medium",
        )

    if counts.get("unwrap", 0) + counts.get("expect", 0) > 10:
        add(
            "Frequent unwrap/expect",
            "Review whether attacker-controlled inputs can trigger abort/DoS or bypass intended error handling.",
            "low",
        )

    if not anchor_programs:
        add(
            "No Anchor.toml program mapping found",
            "Source↔deployment provenance will need declare_id/IDL/docs/build evidence.",
            "low",
        )

    return signals


def build_report(root: Path) -> dict:
    counts: Dict[str, int] = {}
    examples: Dict[str, List[dict]] = {}
    declared_ids = []
    errors = []
    files = list(iter_files(root))

    for path in files:
        file_counts, file_ids, file_examples = scan_file(path, root)
        if isinstance(file_examples, dict) and "error" in file_examples:
            errors.append(file_examples)
            continue
        merge_counts(counts, file_counts)
        declared_ids.extend(file_ids)
        merge_examples(examples, file_examples)

    anchor_programs = parse_anchor_programs(root)
    toolchain = inspect_toolchain(root)

    return {
        "target": str(root.resolve()),
        "files_scanned": len(files),
        "declared_program_ids": declared_ids,
        "anchor_programs": anchor_programs,
        "toolchain_hints": toolchain,
        "counts": dict(sorted(counts.items())),
        "review_signals": derive_review_signals(counts, anchor_programs),
        "examples": examples,
        "errors": errors,
        "disclaimer": "Pattern matches are review signals, not vulnerabilities.",
    }


def print_text(report: dict) -> None:
    print("Solana Zombie Audit - Source Triage")
    print("=" * 36)
    print(f"Target: {report['target']}")
    print(f"Files scanned: {report['files_scanned']}")
    print()

    if report["declared_program_ids"]:
        print("declare_id! values:")
        for item in report["declared_program_ids"]:
            print(f"  {item['program_id']}  ({item['file']}:{item['line']})")
        print()

    if report["anchor_programs"]:
        print("Anchor.toml programs:")
        for item in report["anchor_programs"]:
            print(
                f"  [{item['cluster']}] {item['name']} = {item['program_id']} "
                f"(line {item['line']})"
            )
        print()

    if report["toolchain_hints"]:
        print("Toolchain hints:")
        for key, value in sorted(report["toolchain_hints"].items()):
            print(f"  {key}: {value}")
        print()

    print("Pattern counts:")
    for key, value in report["counts"].items():
        if value:
            print(f"  {key:24} {value}")
    print()

    print("Review signals:")
    if not report["review_signals"]:
        print("  (none generated by heuristics)")
    else:
        for idx, item in enumerate(report["review_signals"], start=1):
            print(f"  {idx}. [{item['priority']}] {item['signal']}")
            print(f"     {item['reason']}")
    print()

    print("Examples:")
    interesting = [
        "remaining_accounts",
        "unchecked_account",
        "raw_account_info",
        "invoke_signed",
        "create_program_address",
        "token_2022",
        "oracle",
    ]
    shown = False
    for key in interesting:
        values = report["examples"].get(key, [])
        if not values:
            continue
        shown = True
        print(f"  {key}:")
        for item in values[:5]:
            print(f"    {item['file']}:{item['line']}  {item['text']}")
    if not shown:
        print("  (no selected examples)")
    print()
    print("NOTE: These are review signals, not confirmed vulnerabilities.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lightweight Solana/Anchor source triage for authorized legacy-program review."
    )
    parser.add_argument("path", help="Repository, program directory, or Rust/TOML file")
    parser.add_argument("--json", dest="json_path", help="Write full JSON report to this path")
    args = parser.parse_args()

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    report = build_report(root)
    print_text(report)

    if args.json_path:
        out = Path(args.json_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON written: {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
