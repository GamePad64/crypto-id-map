#!/usr/bin/env python3
"""Check the OIDs structurally, because no registry will check them for us.

NIST CSOR publishes its arc as HTML; ANSI's and RSADSI's arcs are not published
as data at all. Only the PKIX arc has a machine-readable registry, and
`check_iana.py` covers it. So the OIDs here — the largest single column in the
map — have no upstream to diff against.

What is still checkable without one:

1. **Syntax.** A dotted-decimal OID with no empty arcs and no leading zeros
   (`1.2.0840` is a different OID from `1.2.840`, and almost certainly a typo).
2. **A known root.** Every OID in the map should descend from an arc we can
   name. One that does not is either a mistake or a source worth documenting.
3. **Agreement across files.** The same algorithm appearing in two files must
   carry the same OID. This is what actually catches a fat-fingered digit,
   since a typo is unlikely to be repeated identically.

This is weaker than a registry diff and says so. It is the difference between
"these values are well-formed and self-consistent" and "these values are
correct", and only the first is available here.

Usage:
    uv run check_oids.py
"""

from __future__ import annotations

import csv
import re
import sys
from collections import defaultdict

import click
from rich.table import Table

from registrycheck import DATA_DIR, console

OID_COLUMNS = ("x509_oid", "spki_oid")

# Arcs the map draws on. The point is not completeness — it is that an OID
# under none of these is unexplained, and an unexplained OID is worth a look.
KNOWN_ARCS: dict[str, str] = {
    "1.2.840.10045": "ANSI X9.62 — elliptic curve",
    "1.2.840.113549": "RSADSI — PKCS",
    "1.3.6.1.4.1": "IANA private enterprise numbers",
    "1.3.6.1.5.5.7": "PKIX (checked against IANA's SMI registry by check_iana.py)",
    "1.3.101": "IETF — Ed25519, Ed448, X25519, X448 (RFC 8410)",
    "1.3.132.0": "SECG — SEC 2 curves",
    "2.16.840.1.101.3.4": "NIST CSOR — AES, SHA, ML-DSA, ML-KEM",
}

# Strictly formed, no leading zeros in any arc other than a bare 0.
OID_RE = re.compile(r"^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+$")


def split_oids(cell: str) -> list[str]:
    """One cell may hold several OIDs.

    An EC SubjectPublicKeyInfo needs two — the algorithm and the curve — and the
    map writes them as `1.2.840.10045.2.1 + 1.2.840.10045.3.1.7`.
    """
    return [part.strip() for part in cell.split("+") if part.strip()]


def arc_of(oid: str) -> str | None:
    """The longest known arc this OID descends from."""
    matches = [arc for arc in KNOWN_ARCS if oid == arc or oid.startswith(arc + ".")]
    return max(matches, key=len) if matches else None


@click.command()
def main() -> None:
    """Check OID syntax, arcs, and agreement across files."""
    malformed: list[tuple[str, str, str, str]] = []
    unknown_arc: list[tuple[str, str, str, str]] = []
    by_algorithm: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    arc_counts: dict[str, int] = defaultdict(int)
    total = 0

    for path in sorted(DATA_DIR.glob("*.csv")):
        with path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                name = (row.get("algorithm") or row.get("key_type") or "?").strip()
                for column in OID_COLUMNS:
                    cell = (row.get(column) or "").strip()
                    if not cell:
                        continue
                    for oid in split_oids(cell):
                        total += 1
                        if not OID_RE.match(oid):
                            malformed.append((path.name, name, column, oid))
                            continue
                        arc = arc_of(oid)
                        if arc is None:
                            unknown_arc.append((path.name, name, column, oid))
                        else:
                            arc_counts[arc] += 1
                        by_algorithm[name][path.name].add(oid)

    problems = 0

    if malformed:
        table = Table(title=f"Malformed ({len(malformed)})", title_style="bold red",
                      title_justify="left", header_style="bold")
        for heading in ("File", "Algorithm", "Column", "OID"):
            table.add_column(heading)
        for entry in malformed:
            table.add_row(*entry)
        console.print(table)
        console.print()
        problems += len(malformed)

    if unknown_arc:
        table = Table(title=f"Unknown arc ({len(unknown_arc)})",
                      title_style="bold yellow", title_justify="left",
                      header_style="bold")
        for heading in ("File", "Algorithm", "Column", "OID"):
            table.add_column(heading)
        for entry in unknown_arc:
            table.add_row(*entry)
        console.print(table)
        console.print("[dim]Either a mistake, or an arc worth adding to KNOWN_ARCS "
                      "with a note on where it comes from.[/]\n")
        problems += len(unknown_arc)

    # The same algorithm in two files must carry the same OIDs. A typo is
    # unlikely to be made identically twice, so a disagreement here is the
    # closest thing to a correctness check available without a registry.
    #
    # Compared as sets per file, not as one pooled set: an EC
    # SubjectPublicKeyInfo legitimately carries two OIDs — the algorithm and the
    # curve — and pooling them would read that as a conflict with itself.
    disagreements = [
        (name, files) for name, files in by_algorithm.items()
        if len(files) > 1 and len({frozenset(oids) for oids in files.values()}) > 1
    ]
    if disagreements:
        table = Table(title=f"Same algorithm, different OIDs ({len(disagreements)})",
                      title_style="bold red", title_justify="left",
                      header_style="bold")
        table.add_column("Algorithm")
        table.add_column("Where")
        for name, files in disagreements:
            where = "; ".join(
                f"{filename}: {', '.join(sorted(oids))}"
                for filename, oids in sorted(files.items())
            )
            table.add_row(name, where)
        console.print(table)
        console.print()
        problems += len(disagreements)

    table = Table(title="Arcs in use", title_style="bold", title_justify="left",
                  header_style="bold")
    table.add_column("Arc", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Source")
    for arc, count in sorted(arc_counts.items(), key=lambda kv: -kv[1]):
        table.add_row(arc, str(count), KNOWN_ARCS[arc])
    console.print(table)
    console.print()

    console.print(f"Checked [bold]{total}[/] OIDs for syntax, arc and consistency.")
    if problems == 0:
        console.print("[bold green]All well-formed, all from known arcs, "
                      "all consistent across files.[/]")

    console.print(
        "\n[dim]This is not a registry check. NIST CSOR publishes its arc as "
        "HTML and the ANSI and RSADSI arcs are not published as data at all, so "
        "the values cannot be diffed against a source. Only the PKIX arc has a "
        "registry, and check_iana.py covers it.[/]"
    )

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
