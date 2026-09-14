"""Check that the CSV files are well-formed and internally consistent.

The cheapest failure in a CSV table is also the easiest to miss: a stray comma
in a note shifts every later column by one, so an OID lands in `status` and a
status lands in `notes`. Nothing downstream would call that an error — the
registry checks read named columns, find something there, and compare it
happily.

This runs before the registry checks are worth trusting: column counts, a header
on every file, and no two rows naming the same algorithm.

It deliberately does *not* flag a repeated identifier. A first version did, and
every one of its 22 findings was the map doing its job: `1.2.840.113549.1.1.10`
is the OID for six different RSA-PSS rows, because PSS carries its hash in ASN.1
parameters rather than in the OID; `ES256` appears twice because TLS splits what
JOSE keeps as one name. Those collisions are the asymmetries this document
exists to record, so a check that calls them errors is a check pointed the wrong
way.

It needs no network, which makes it the one check that always runs.
"""

from __future__ import annotations

import csv
import sys
from collections import Counter

import click
from rich.table import Table

from registrycheck import DATA_DIR, console

def check() -> tuple[list[str], int, int]:
    problems: list[str] = []
    files = rows_total = 0

    for path in sorted(DATA_DIR.glob("*.csv")):
        files += 1
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))

        if not rows:
            problems.append(f"{path.name}: empty file")
            continue

        header = rows[0]
        width = len(header)
        if width < 2:
            problems.append(f"{path.name}: header has {width} column(s)")
        if any(not cell.strip() for cell in header):
            problems.append(f"{path.name}: header has an unnamed column")

        body = [r for r in rows[1:] if r]
        rows_total += len(body)

        for number, row in enumerate(body, start=2):
            if len(row) != width:
                # The usual cause is an unquoted comma inside a note.
                problems.append(
                    f"{path.name}:{number}: {len(row)} fields, header has {width}"
                )

        clean = [r for r in body if len(r) == width]

        # Two rows naming the same algorithm are a merge accident.
        if "algorithm" in [h.strip() for h in header]:
            index = [h.strip() for h in header].index("algorithm")
            names = [r[index].strip() for r in clean if r[index].strip()]
            for name, count in Counter(names).items():
                if count > 1:
                    problems.append(
                        f"{path.name}: algorithm {name!r} appears {count} times"
                    )

    return problems, files, rows_total


@click.command()
def main() -> None:
    """Check CSV structure: column counts, headers, duplicate algorithm names."""
    problems, files, rows = check()

    if problems:
        table = Table(title=f"Problems ({len(problems)})", title_style="bold red",
                      title_justify="left", header_style="bold", show_header=False)
        table.add_column("", style="yellow")
        for problem in problems:
            table.add_row(problem)
        console.print(table)
        console.print()

    console.print(f"Checked [bold]{rows}[/] rows across [bold]{files}[/] files.")
    if not problems:
        console.print("[bold green]Every row is well-formed.[/]")

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
