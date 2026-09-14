#!/usr/bin/env python3
"""Check `key-params.csv` — the field labels inside COSE_Key and JWK.

Separate from the algorithm checks because the thing being identified is
different: not an algorithm but a *field within a container*, and the two
containers disagree about several of them. That disagreement is the reason the
file exists — COSE writes `dP`/`dQ`/`qInv` where JWK writes `dp`/`dq`/`qi`, so a
name-based mapper silently drops three of four RSA CRT parameters.

The registries are shaped differently from the algorithm ones, which is why the
shared machinery does not fit:

- **COSE splits its labels across two registries.** Common parameters (`kty`=1,
  `kid`=2) live in one; type-specific ones (`crv`=-1, `x`=-2) in another, keyed
  by *(key type, label)* — the same label means different things under different
  key types, so a flat lookup would be wrong.
- **JWK has no numbers at all.** The identifier is the parameter name itself, so
  the check is existence rather than value agreement.

Usage:
    uv run check_key_params.py            # report, exit 1 on any mismatch
    uv run check_key_params.py --new      # also list parameters we don't cite
    uv run check_key_params.py --offline  # use cached responses
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass, field

import click
import niquests

from registrycheck import (
    DATA_DIR,
    PLACEHOLDER_NAMES,
    console,
    fetch,
    findings_table,
    make_session,
    Finding,
    Report,
)

COSE_COMMON = "https://www.iana.org/assignments/cose/key-common-parameters.csv"
COSE_BY_TYPE = "https://www.iana.org/assignments/cose/key-type-parameters.csv"
JWK_PARAMS = "https://www.iana.org/assignments/jose/web-key-parameters.csv"

# `key-params.csv` says which COSE key type a row belongs to; the registry says
# it as a number. Anything not listed here is a common parameter, which lives in
# the other registry and has no key type.
SCOPE_TO_KTY = {
    "OKP": "1",
    "EC2": "2",
    "RSA": "3",
    "Symmetric": "4",
    "HSS-LMS": "5",
    "AKP": "7",
}

# Parameters our file lists that no registry will confirm, with the reason.
# Every one of these is a real property of the map rather than an omission.
ACCEPTED: dict[tuple[str, str], str] = {
    ("jwk", "x5u x5c x5t x5t#S256"):
        "one row standing for four separate registered parameters",
    ("cose", "x5u x5c x5t x5t#S256"):
        "COSE keeps these in its own x5 registry, not the key parameters one",
    ("cose", "separate COSE x5 registry"):
        "a pointer rather than a label",
    ("jwk", "r"):
        "a member of the `oth` array, not a top-level JWK parameter, so the "
        "registry has no entry for it",
    ("jwk", "t"): "same as `r`: inside `oth`",
    ("jwk", "d"):
        "`d` appears twice in JWK — the private exponent at the top level and a "
        "CRT coefficient inside `oth`. Only the first is registered",
}


@dataclass
class ParamReport(Report):
    """A Report that counts parameters instead of registries."""

    sources_read: int = 0


def read_cose_labels(
    session: niquests.Session | None, *, offline: bool
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    """COSE labels as ({label: name}, {(kty, label): name}).

    Two dictionaries because the registry is two registries: common labels apply
    to every key type, type-specific ones only under their own.
    """
    common: dict[str, str] = {}
    body = fetch(session, COSE_COMMON, offline=offline)
    for row in csv.DictReader(body.splitlines()):
        name = (row.get("Name") or "").strip()
        label = (row.get("Label") or "").strip()
        if not name or PLACEHOLDER_NAMES.match(name) or not label.lstrip("-").isdigit():
            continue
        common[label] = name

    by_type: dict[tuple[str, str], str] = {}
    body = fetch(session, COSE_BY_TYPE, offline=offline)
    for row in csv.DictReader(body.splitlines()):
        name = (row.get("Name") or "").strip()
        label = (row.get("Label") or "").strip()
        kty = (row.get("Key Type") or "").strip()
        if not name or PLACEHOLDER_NAMES.match(name) or not label.lstrip("-").isdigit():
            continue
        by_type[(kty, label)] = name

    return common, by_type


def read_jwk_params(
    session: niquests.Session | None, *, offline: bool
) -> dict[str, str]:
    """JWK parameter names as {name: description}."""
    body = fetch(session, JWK_PARAMS, offline=offline)
    params: dict[str, str] = {}
    for row in csv.DictReader(body.splitlines()):
        name = (row.get("Parameter Name") or "").strip()
        if not name or PLACEHOLDER_NAMES.match(name):
            continue
        params[name] = (row.get("Parameter Description") or "").strip()
    return params


def check(*, offline: bool, find_new: bool) -> ParamReport:
    report = ParamReport(registries_total=3)
    session = None if offline else make_session()

    try:
        try:
            cose_common, cose_by_type = read_cose_labels(session, offline=offline)
            report.sources_read += 2
        except (niquests.RequestException, ValueError, OSError) as exc:
            report.fetch_errors.append(f"COSE key parameters: {exc}")
            cose_common, cose_by_type = {}, {}

        try:
            jwk_params = read_jwk_params(session, offline=offline)
            report.sources_read += 1
        except (niquests.RequestException, ValueError, OSError) as exc:
            report.fetch_errors.append(f"JWK parameters: {exc}")
            jwk_params = {}
    finally:
        if session is not None:
            session.close()

    report.registries_read = report.sources_read
    report.registries_total = 3

    path = DATA_DIR / "key-params.csv"
    cited_cose: set[str] = set()
    cited_jwk: set[str] = set()

    with path.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            scope = (row.get("scope") or "").strip()
            our_field = (row.get("field") or "").strip()
            cose_label = (row.get("cose_label") or "").strip()
            jwk_name = (row.get("jwk_name") or "").strip()

            if cose_label and cose_common | cose_by_type:
                report.checked += 1
                cited_cose.add(cose_label)
                kty = SCOPE_TO_KTY.get(scope)
                registry_name = (
                    cose_by_type.get((kty, cose_label)) if kty else None
                ) or cose_common.get(cose_label)

                if ("cose", cose_label) in ACCEPTED:
                    pass
                elif registry_name is None:
                    report.findings.append(Finding(
                        "missing", f"cose/{scope}", cose_label,
                        ours=our_field, source_file="key-params.csv",
                    ))
                elif registry_name.lower() != our_field.lower():
                    # Exact match, case-insensitive. Unlike algorithm names,
                    # these are short identifiers with no spelling latitude —
                    # `dP` against `dp` is precisely the difference the file
                    # documents, so the comparison must not smooth it away.
                    report.findings.append(Finding(
                        "mismatch", f"cose/{scope}", cose_label,
                        ours=our_field, theirs=registry_name,
                        source_file="key-params.csv",
                    ))

            if jwk_name and jwk_params:
                report.checked += 1
                cited_jwk.add(jwk_name)
                if ("jwk", jwk_name) in ACCEPTED:
                    pass
                elif jwk_name not in jwk_params:
                    report.findings.append(Finding(
                        "missing", "jwk", jwk_name,
                        ours=our_field, source_file="key-params.csv",
                    ))

    if find_new:
        for label, name in sorted(cose_common.items(), key=lambda kv: int(kv[0])):
            if label not in cited_cose:
                report.findings.append(Finding(
                    "new", "cose/common", label, theirs=name))
        for (kty, label), name in sorted(cose_by_type.items()):
            if label not in cited_cose:
                report.findings.append(Finding(
                    "new", f"cose/kty{kty}", label, theirs=name))
        for name, description in sorted(jwk_params.items()):
            if name not in cited_jwk:
                report.findings.append(Finding(
                    "new", "jwk", name, theirs=description or name))

    return report


@click.command()
@click.option("--new", "find_new", is_flag=True,
              help="Also list registered parameters the map does not cite.")
@click.option("--offline", is_flag=True,
              help="Use cached responses instead of fetching.")
def main(find_new: bool, offline: bool) -> None:
    """Check COSE_Key and JWK field labels against their registries."""
    with console.status("Reading key parameter registries..."):
        report = check(offline=offline, find_new=find_new)

    if report.fetch_errors:
        console.print(f"[bold red]Could not read ({len(report.fetch_errors)})[/]")
        for error in report.fetch_errors:
            console.print(f"  {error}")
        console.print()

    if report.problems:
        console.print(findings_table(
            f"Problems ({len(report.problems)})", report.problems, style="bold red"
        ))
        console.print()

    if report.additions:
        console.print(findings_table(
            f"Registered but not in the map ({len(report.additions)})",
            report.additions,
            style="bold yellow",
        ))
        console.print()

    console.print(
        f"Checked [bold]{report.checked}[/] field labels across "
        f"[bold]{report.registries_read}/{report.registries_total}[/] registries."
    )

    if not report.problems and not report.fetch_errors:
        console.print("[bold green]No disagreements with the registries.[/]")
    if not find_new:
        console.print(
            "[dim]Run with --new to see parameters the map does not cite.[/]"
        )

    sys.exit(1 if (report.problems or report.fetch_errors) else 0)


if __name__ == "__main__":
    main()
