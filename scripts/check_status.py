"""Check the `status` column against what the registries say.

`status` is the one column a reader is likely to act on — it is the difference
between "ship this" and "do not" — and it was written by hand, which means it
was the least trustworthy column in the map. Every other check compares an
identifier to a registry; nothing compared this.

It is checkable because IANA publishes the evidence. Each registry row carries a
`Reference` naming the documents that define it (`[RFC9053]`, `[draft-ietf-
tls-mldsa-00]`), and several carry a `Recommended` column whose `D` means
"Discouraged" in so many words. A row citing only drafts cannot be `rfc`; a row
the registry discourages should not read as though it were current.

What this does NOT do is derive the status and demand equality. A status is a
claim about an algorithm, and a row may cite several registries that disagree —
which is exactly what `mixed` is for. The test is *compatibility*: is the claim
consistent with the evidence? That is the strongest test the sources support,
and it still catches the errors that matter (a draft called an RFC, a
discouraged algorithm presented as live).
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass

import click
import niquests
from rich.table import Table

from check_iana import REGISTRIES
from registrycheck import (
    DATA_DIR,
    console,
    fetch,
    make_session,
    normalise_value,
    our_cell_values,
)

# What each status asserts, in terms a registry can contradict.
#
# `mixed` and `other` assert nothing checkable — they exist because an algorithm
# can be an RFC in one registry and a draft in another, and saying so is more
# honest than picking one. They are listed so an unknown status is still an
# error.
STATUSES = {"rfc", "draft", "deprecated", "obsolete", "early-alloc", "mixed",
            "none", "other"}

# Statuses claiming the algorithm is defined by a published RFC.
CLAIMS_RFC = {"rfc", "deprecated", "obsolete"}


@dataclass
class Problem:
    file: str
    algorithm: str
    ours: str
    evidence: str


@dataclass
class Evidence:
    """What the registries carrying a row say about it."""

    rfcs: set[str]
    drafts: set[str]
    discouraged: bool
    registries: set[str]

    @property
    def cited(self) -> bool:
        return bool(self.registries)


def registry_evidence(
    session: niquests.Session | None, *, offline: bool
) -> tuple[dict[tuple[str, str], Evidence], list[str]]:
    """Read every registry once, as {(our_column, value): Evidence}.

    Keyed by column *and* value because the same number means different things
    in different registries: COSE `-8` is EdDSA, HPKE `0x0010` is a KEM.
    """
    evidence: dict[tuple[str, str], Evidence] = {}
    errors: list[str] = []

    for reg in REGISTRIES:
        try:
            body = fetch(session, reg.url, offline=offline)
        except (niquests.RequestException, ValueError, OSError) as exc:
            errors.append(f"{reg.key}: {exc}")
            continue

        for row in csv.DictReader(body.splitlines()):
            cells = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            value = normalise_value(cells.get(reg.value_column, ""), reg.normalise)
            if value is None:
                continue

            reference = cells.get("Reference", "")
            recommended = cells.get("Recommended", "")

            key = (reg.our_column, value)
            existing = evidence.get(key)
            found = Evidence(
                rfcs=set(re.findall(r"RFC-?(\d+)", reference)),
                # `RFC-ietf-...` is an RFC-to-be: approved, not yet numbered.
                drafts=set(re.findall(r"(draft-[\w.-]+|RFC-ietf-[\w.-]+)", reference)),
                discouraged=recommended.upper() == "D",
                registries={reg.key},
            )
            if existing is None:
                evidence[key] = found
            else:
                existing.rfcs |= found.rfcs
                existing.drafts |= found.drafts
                existing.discouraged |= found.discouraged
                existing.registries |= found.registries

    return evidence, errors


def row_evidence(
    row: dict[str, str], evidence: dict[tuple[str, str], Evidence]
) -> Evidence:
    """Pool the evidence from every registry this row cites."""
    pooled = Evidence(set(), set(), False, set())
    for reg in REGISTRIES:
        cell = (row.get(reg.our_column) or "").strip()
        if not cell:
            continue
        for value in our_cell_values(reg, cell):
            found = evidence.get((reg.our_column, value))
            if found is None:
                continue
            pooled.rfcs |= found.rfcs
            pooled.drafts |= found.drafts
            pooled.discouraged |= found.discouraged
            pooled.registries |= found.registries
    return pooled


def contradiction(status: str, found: Evidence) -> str:
    """Why the evidence contradicts the claim, or "" if it does not.

    Silence where there is no evidence is deliberate. Half the map's identifiers
    are OIDs and national-standard numbers with no machine-readable registry
    behind them, and reporting every one of those as a problem would bury the
    rows that genuinely disagree.
    """
    if not found.cited:
        return ""

    seen = ", ".join(sorted(found.registries))

    if status in CLAIMS_RFC and not found.rfcs and found.drafts:
        return (f"{seen} cite only drafts "
                f"({', '.join(sorted(found.drafts)[:2])})")

    if status == "draft" and found.rfcs and not found.drafts:
        return f"{seen} cite RFC {', '.join(sorted(found.rfcs)[:2])}"

    # `Recommended=D` is IANA saying "Discouraged" in a column, not in prose.
    # A row carrying that while claiming to be plain `rfc` reads as current when
    # the registry says it is not.
    if found.discouraged and status == "rfc":
        return f"{seen} mark it Recommended=D (Discouraged)"

    return ""


def check(session: niquests.Session | None, *, offline: bool) -> tuple[list[Problem], int, int, list[str]]:
    evidence, errors = registry_evidence(session, offline=offline)
    problems: list[Problem] = []
    checked = unbacked = 0

    for path in sorted(DATA_DIR.glob("*.csv")):
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if not rows or "status" not in rows[0]:
            continue

        for row in rows:
            status = (row.get("status") or "").strip()
            name = (row.get("algorithm") or row.get("key_type") or "?").strip()

            if status not in STATUSES:
                problems.append(Problem(path.name, name, status,
                                        f"not one of {', '.join(sorted(STATUSES))}"))
                continue

            found = row_evidence(row, evidence)
            if not found.cited:
                unbacked += 1
                continue

            checked += 1
            if why := contradiction(status, found):
                problems.append(Problem(path.name, name, status, why))

    return problems, checked, unbacked, errors


@click.command()
@click.option("--offline", is_flag=True,
              help="Use the cached registries instead of fetching.")
def main(offline: bool) -> None:
    """Check the status column against registry references."""
    session = None if offline else make_session()
    try:
        with console.status("Reading the registries..."):
            problems, checked, unbacked, errors = check(session, offline=offline)
    finally:
        if session is not None:
            session.close()

    if errors:
        console.print(f"[bold red]Could not read ({len(errors)})[/]")
        for error in errors:
            console.print(f"  {error}")
        console.print()

    if problems:
        table = Table(title=f"Problems ({len(problems)})", title_style="bold red",
                      title_justify="left", header_style="bold")
        table.add_column("File", style="dim", no_wrap=True)
        table.add_column("Algorithm", style="cyan")
        table.add_column("Status", style="yellow", no_wrap=True)
        table.add_column("But the registries say")
        for problem in problems:
            table.add_row(problem.file, problem.algorithm, problem.ours,
                          problem.evidence)
        console.print(table)
        console.print()

    console.print(
        f"Checked [bold]{checked}[/] status cells against registry references; "
        f"[bold]{unbacked}[/] cite no machine-readable registry."
    )
    if not problems and not errors:
        console.print("[bold green]No status contradicts its registries.[/]")

    console.print(
        "\n[dim]The rows with no registry behind them are OIDs and national "
        "standards; their status rests on the reference in the notes.[/]"
    )
    sys.exit(1 if (problems or errors) else 0)


if __name__ == "__main__":
    main()
