"""Check `tls-cipher-suites.csv` against the IANA cipher suite registry.

This file is not a map between registries — every suite has exactly one
identifier, assigned in one place — so the shared value/name machinery does not
fit it. What needs checking is different: the suite number, the exact name, the
`Recommended` flag, the reference, and whether the columns that decompose a
suite into its parts agree with the name the registry gives it.

The decomposition matters most, because it is the part a human wrote by reading
the name. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` says its own key exchange,
authentication, cipher, key size and hash; a row claiming something else is a
transcription error, and there is no other way to catch one.
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass

import click
import niquests
from rich.table import Table

from registrycheck import DATA_DIR, console, fetch, make_session

REGISTRY_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
OUR_FILE = "tls-cipher-suites.csv"


@dataclass
class Problem:
    value: str
    column: str
    ours: str
    theirs: str


def suite_value(raw: str) -> str | None:
    """Normalise a suite number to `0xNNNN`.

    IANA writes a suite as two bytes, `"0x13,0x01"`; we write it as one number,
    `0x1301`. Both spellings are accepted so the two sides can be compared.
    Ranges (`0x00,0x1C-1D`) describe holes, not suites.
    """
    text = raw.strip().replace('"', "")
    if not text:
        return None
    if re.fullmatch(r"0x[0-9A-Fa-f]{4}", text):
        return f"0x{text[2:].upper()}"
    parts = [p.strip() for p in text.split(",")]
    digits = ""
    for part in parts:
        if not re.fullmatch(r"0x[0-9A-Fa-f]{2}", part):
            return None  # a range or something else that is not one suite
        digits += part[2:]
    if not digits:
        return None
    return f"0x{digits.upper()}"


def read_registry(session: niquests.Session | None, *, offline: bool) -> dict[str, dict[str, str]]:
    body = fetch(session, REGISTRY_URL, offline=offline)
    rows = csv.DictReader(body.splitlines())
    entries: dict[str, dict[str, str]] = {}
    for row in rows:
        value = suite_value(row.get("Value") or "")
        name = (row.get("Description") or "").strip()
        if value is None or not name or name.lower().startswith(("unassigned", "reserved")):
            continue
        entries[value] = {
            "name": name,
            "recommended": (row.get("Recommended") or "").strip(),
            "reference": (row.get("Reference") or "").strip(),
        }
    return entries


def references_agree(ours: str, theirs: str) -> bool:
    """Do our reference and the registry's cite the same documents?

    We write `RFC 9846`, IANA writes `[RFC9846]`, and either side may list
    several. Our text sometimes adds context the registry does not carry
    ("RFC 9846 + IESG action 2018-08-16"), so the test is that every RFC the
    registry names also appears in ours — not that the strings match.
    """
    ours_rfcs = set(re.findall(r"RFC\s*-?\s*(\d+)", ours, re.IGNORECASE))
    theirs_rfcs = set(re.findall(r"RFC\s*-?\s*(\d+)", theirs, re.IGNORECASE))
    if not theirs_rfcs:
        return True
    return theirs_rfcs <= ours_rfcs


# How a suite name spells each part we record in its own column. The name is
# the authority: it is assigned by IANA and cannot drift.
#
# Written as name-fragment -> the values we accept in that column, because one
# fragment can be spelled several ways in prose (`AES-GCM` for the mode,
# `AES-CCM-8` for the truncated-tag variant).
KX_IN_NAME = {
    "ECDHE_ECDSA": "ECDHE", "ECDHE_RSA": "ECDHE", "ECDHE_PSK": "ECDHE",
    "DHE_RSA": "DHE", "DHE_DSS": "DHE", "DHE_PSK": "DHE",
    "ECDH_ECDSA": "ECDH", "ECDH_RSA": "ECDH",
    "SRP_SHA": "SRP", "KRB5": "KRB5",
}
AUTH_IN_NAME = {
    "ECDHE_ECDSA": "ECDSA", "ECDH_ECDSA": "ECDSA",
    "ECDHE_RSA": "RSA", "ECDH_RSA": "RSA", "DHE_RSA": "RSA",
    "ECDHE_PSK": "PSK", "DHE_PSK": "PSK",
    "DHE_DSS": "DSS",
}


def name_parts(name: str) -> dict[str, str]:
    """What the suite name itself says about its parts.

    Returns only what the name states. A TLS 1.3 suite names no key exchange and
    no authentication, so those keys are absent rather than empty — absent means
    "the name does not say", which is not the same as "the name says none".
    """
    parts: dict[str, str] = {}
    body = name.removeprefix("TLS_")

    for fragment, value in KX_IN_NAME.items():
        if body.startswith(fragment + "_"):
            parts["kx"] = value
            break
    for fragment, value in AUTH_IN_NAME.items():
        if body.startswith(fragment + "_"):
            parts["auth"] = value
            break

    if match := re.search(r"AES_(128|256)_(GCM|CCM_8|CCM|CBC)", body):
        bits, mode = match.groups()
        parts["key_bits"] = bits
        parts["cipher_mode"] = {"GCM": "AES-GCM", "CCM": "AES-CCM",
                                "CCM_8": "AES-CCM-8", "CBC": "AES-CBC"}[mode]
    elif "CHACHA20_POLY1305" in body:
        parts["key_bits"] = "256"
        parts["cipher_mode"] = "ChaCha20-Poly1305"

    # The trailing hash. In TLS 1.3 it is the HKDF hash, in TLS 1.2 the PRF and
    # MAC hash; either way the name ends with it.
    if match := re.search(r"_SHA(256|384|512)$", body):
        parts["mac_prf_hash"] = f"SHA-{match.group(1)}"
    elif body.endswith("_SHA"):
        parts["mac_prf_hash"] = "SHA-1"

    return parts


def check(session: niquests.Session | None, *, offline: bool, find_new: bool) -> tuple[list[Problem], int, list[str]]:
    registry = read_registry(session, offline=offline)
    problems: list[Problem] = []
    cited: set[str] = set()

    path = DATA_DIR / OUR_FILE
    with path.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            value = suite_value(row["value"])
            if value is None:
                problems.append(Problem(row["value"], "value", row["value"],
                                        "not a suite number"))
                continue
            cited.add(value)

            entry = registry.get(value)
            if entry is None:
                problems.append(Problem(value, "value", row["name"],
                                        "not assigned in the registry"))
                continue

            # The name is compared exactly. Unlike a cross-registry map, where
            # each registry spells an algorithm its own way, a suite name is a
            # single assigned string — any difference is an error.
            if row["name"].strip() != entry["name"]:
                problems.append(Problem(value, "name", row["name"], entry["name"]))

            if row["recommended"].strip() != entry["recommended"]:
                problems.append(Problem(value, "recommended",
                                        row["recommended"], entry["recommended"]))

            if not references_agree(row["reference"], entry["reference"]):
                problems.append(Problem(value, "reference",
                                        row["reference"], entry["reference"]))

            # The decomposition, against the name the registry just confirmed.
            stated = name_parts(entry["name"])
            for column, expected in stated.items():
                ours = (row.get(column) or "").strip()
                if ours != expected:
                    problems.append(Problem(value, column, ours or "(empty)",
                                            f"{expected} (from the name)"))

    new: list[str] = []
    if find_new:
        new = [f"{v}  {registry[v]['name']}" for v in sorted(registry) if v not in cited]

    return problems, len(cited), new


@click.command()
@click.option("--new", "find_new", is_flag=True,
              help="Also list assigned suites the map does not carry.")
@click.option("--offline", is_flag=True,
              help="Use the cached registry instead of fetching.")
def main(find_new: bool, offline: bool) -> None:
    """Check the TLS cipher suite table against IANA."""
    session = None if offline else make_session()
    try:
        with console.status("Reading the TLS cipher suite registry..."):
            problems, checked, new = check(session, offline=offline, find_new=find_new)
    except (niquests.RequestException, ValueError, OSError) as exc:
        console.print(f"[bold red]Could not read the registry:[/] {exc}")
        sys.exit(1)
    finally:
        if session is not None:
            session.close()

    if problems:
        table = Table(title=f"Problems ({len(problems)})", title_style="bold red",
                      title_justify="left", header_style="bold")
        table.add_column("Suite", style="yellow", no_wrap=True)
        table.add_column("Column", style="cyan", no_wrap=True)
        table.add_column("Ours")
        table.add_column("Registry says")
        for problem in problems:
            table.add_row(problem.value, problem.column, problem.ours, problem.theirs)
        console.print(table)
        console.print()

    if new:
        console.print(f"[bold yellow]Assigned but not in the map ({len(new)})[/]")
        for line in new:
            console.print(f"  {line}")
        console.print()

    console.print(f"Checked [bold]{checked}[/] cipher suites against IANA.")
    if not problems:
        console.print("[bold green]No disagreements with IANA.[/]")
    if not find_new:
        console.print("[dim]Run with --new to see the suites the map leaves out.[/]")

    console.print(
        "\n[dim]Not checked here: notes (prose, no machine-readable source).[/]"
    )
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
