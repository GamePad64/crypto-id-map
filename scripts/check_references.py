"""Check the RFC numbers cited in prose against the IETF datatracker.

The `notes` column is the one part of the map with no machine-readable source
behind it, and it is where the map's one published factual error lived: a note
asserting that two TLS codepoints "held GOST under RFC 9189" and were later
reallocated. Both halves were wrong, and every existing check passed, because
nothing reads prose.

Prose cannot be verified. But a number in prose can. This checks the part of a
note that is falsifiable:

  * the RFC exists — a transposed or invented number 404s;
  * its status is not misrepresented — an Informational or Experimental RFC
    described as though it were a standard. RFC 9189, the document at the
    centre of the GOST error, is Informational from the Independent stream,
    which is exactly the kind of thing a note should not call a standard.

An earlier version also compared the RFC's title against the row's subject, on
the theory that a citation attached to the wrong claim would show up as a title
with nothing in common with its row. It was removed: RFC 7518 is "JSON Web
Algorithms", which legitimately defines RSA-OAEP without naming it, and RFC
9106 is "Argon2" beside a row reading "Argon2id". Every one of its findings was
a false positive, and a check that cries wolf on correct data is worse than no
check — it teaches the reader to skip the report.

So this verifies citations, not claims. The prose itself rests on review; see
the coverage table in scripts/README.md for what that leaves unguarded.
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass

import click
import niquests
from rich.table import Table

from registrycheck import DATA_DIR, console, make_session

API = "https://datatracker.ietf.org/api/v1/doc/document/rfc{number}/?format=json"

# "RFC 1234 standardises X", "the RFC 1234 standard". Deliberately narrow: the
# bare word `standard` appears in correct notes far more often than in wrong
# ones, so matching it produces noise rather than findings.
CLAIMS_STANDARD = re.compile(
    r"RFC\s*\d{3,5}\s*(?:,[^;]*,)?\s*(?:is\s+)?(?:the\s+)?standardi[sz]e[sd]?\b"
    r"|\bRFC\s*\d{3,5}\s+standard\b"
    r"|\bstandardi[sz]ed\s+(?:in|by)\s+RFC\s*\d{3,5}",
    re.IGNORECASE,
)


@dataclass
class Problem:
    file: str
    algorithm: str
    rfc: str
    issue: str


@dataclass
class Doc:
    title: str
    std_level: str

    @property
    def is_standards_track(self) -> bool:
        return self.std_level in {"ps", "ds", "std"}


def fetch_rfc(session: niquests.Session, number: str) -> Doc | None:
    response = session.get(API.format(number=number), timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    body = response.json()
    level = (body.get("std_level") or "").rstrip("/").rsplit("/", 1)[-1]
    return Doc(title=body.get("title") or "", std_level=level)


def check(session: niquests.Session) -> tuple[list[Problem], int, int]:
    problems: list[Problem] = []
    cache: dict[str, Doc | None] = {}
    citations = 0

    for path in sorted(DATA_DIR.glob("*.csv")):
        with path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                note = (row.get("notes") or "").strip()
                if not note:
                    continue
                name = (row.get("algorithm") or row.get("key_type")
                        or row.get("name") or "?").strip()

                for number in dict.fromkeys(re.findall(r"RFC\s*(\d{3,5})", note)):
                    citations += 1
                    if number not in cache:
                        cache[number] = fetch_rfc(session, number)
                    doc = cache[number]

                    if doc is None:
                        problems.append(Problem(path.name, name, number,
                                                "no such RFC"))
                        continue

                    # An Informational or Experimental RFC called a standard.
                    # Matched on the phrases that assert it, not on the word
                    # alone: a note may say an RFC is *not* standards track, or
                    # that an algorithm is a *national* standard while the RFC
                    # merely describes it — both true, neither a claim about
                    # the RFC's own status.
                    claims_standard = CLAIMS_STANDARD.search(note)
                    if claims_standard and not doc.is_standards_track:
                        problems.append(Problem(
                            path.name, name, number,
                            f"note calls it a standard; it is {doc.std_level or 'unknown'}",
                        ))

    return problems, citations, len(cache)


@click.command()
def main() -> None:
    """Check RFC numbers cited in the notes against the datatracker."""
    session = make_session()
    try:
        with console.status("Asking the datatracker..."):
            problems, citations, distinct = check(session)
    except (niquests.RequestException, ValueError, OSError) as exc:
        console.print(f"[bold red]Could not reach the datatracker:[/] {exc}")
        sys.exit(1)
    finally:
        session.close()

    if problems:
        table = Table(title=f"Problems ({len(problems)})", title_style="bold red",
                      title_justify="left", header_style="bold")
        table.add_column("File", style="dim", no_wrap=True)
        table.add_column("Row", style="cyan")
        table.add_column("RFC", style="yellow", no_wrap=True)
        table.add_column("Issue")
        for problem in problems:
            table.add_row(problem.file, problem.algorithm,
                          f"RFC {problem.rfc}", problem.issue)
        console.print(table)
        console.print()

    console.print(
        f"Checked [bold]{citations}[/] RFC citations in prose "
        f"([bold]{distinct}[/] distinct documents)."
    )
    if not problems:
        console.print("[bold green]Every cited RFC exists and fits its row.[/]")

    console.print(
        "\n[dim]This checks the citations, not the claims. The rest of the "
        "notes column has no machine-readable source and rests on review.[/]"
    )
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
