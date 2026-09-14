#!/usr/bin/env python3
"""Check the map's IANA-sourced identifiers against the live registries.

Two questions, both of which the map goes stale on:

1. **Is what we wrote still true?** A value we cite must exist in the registry
   and name the algorithm we think it names.
2. **What appeared since?** Registries gain entries continuously — ML-DSA
   entered COSE in 2026, composite signature OIDs were allocated in 2025 — and a
   reference that silently misses them is worse than no reference.

Only IANA is covered here. OIDs, multicodec, SSH and PGP identifiers come from
elsewhere and get their own scripts; this one reports them as unchecked rather
than pretending otherwise.

The script never edits the CSV files. A registry diff needs a human to decide
whether the map is wrong or the world moved, and an auto-fix would erase that
distinction.

Usage:
    uv run check_iana.py            # report, exit 1 on any mismatch
    uv run check_iana.py --new      # also list registry entries we don't cite
    uv run check_iana.py --offline  # use cached responses, no network
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import click
import niquests
from platformdirs import user_cache_path
from rich.console import Console
from rich.table import Table

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_DIR = user_cache_path("crypto-id-map", ensure_exists=True) / "registries"
USER_AGENT = "crypto-id-map/1.0 (registry consistency check)"
TIMEOUT = 30

console = Console()


@dataclass(frozen=True)
class Registry:
    """One IANA registry and how to read it.

    Every registry has its own column names and its own idea of where the
    number lives — COSE puts `Name` first and `Value` second, HPKE the other way
    round, and the AEAD registry splits its page into two tables so the data
    sits in a `-2` file. None of that is guessable, so it is spelled out.
    """

    key: str
    """Short name used in report output."""

    url: str
    value_column: str
    name_column: str

    our_files: tuple[str, ...]
    """Which data files cite this registry."""

    our_column: str
    """The column in those files holding this registry's identifier."""

    description_column: str = ""
    """A second column to match against, where the registry has one.

    COSE names `-9` as `ESP256` and describes it as "ECDSA using P-256 curve and
    SHA-256". Our map uses the descriptive form, because relating the short
    names to each other is the whole point of the document. Matching against
    either column lets both spellings pass without loosening the check.
    """

    normalise: str = "int"
    """How to compare values: `int` (decimal), `hex` (0x-prefixed), `str`."""

    notes: str = ""


REGISTRIES: tuple[Registry, ...] = (
    Registry(
        key="cose_alg",
        url="https://www.iana.org/assignments/cose/algorithms.csv",
        value_column="Value",
        name_column="Name",
        description_column="Description",
        our_files=("signatures.csv", "aead.csv", "hash.csv", "kdf.csv", "mac.csv",
                   "keywrap.csv", "cipher.csv"),
        our_column="cose_alg",
    ),
    Registry(
        key="cose_kty",
        url="https://www.iana.org/assignments/cose/key-type.csv",
        value_column="Value",
        name_column="Name",
        description_column="Description",
        our_files=("key-types.csv",),
        our_column="cose_kty",
    ),
    Registry(
        key="cose_crv",
        url="https://www.iana.org/assignments/cose/elliptic-curves.csv",
        value_column="Value",
        name_column="Name",
        description_column="Description",
        our_files=("key-types.csv",),
        our_column="cose_crv",
    ),
    Registry(
        key="iana_aead",
        url="https://www.iana.org/assignments/aead-parameters/aead-parameters-2.csv",
        value_column="Numeric ID",
        name_column="Name",
        our_files=("aead.csv",),
        our_column="iana_aead",
        notes="the registry page holds two tables; the algorithms are in the -2 file",
    ),
    Registry(
        key="hpke_kem",
        url="https://www.iana.org/assignments/hpke/hpke-kem-ids.csv",
        value_column="Value",
        name_column="KEM",
        our_files=("kem.csv",),
        our_column="hpke_kem",
        normalise="hex",
    ),
    Registry(
        key="hpke_kdf",
        url="https://www.iana.org/assignments/hpke/hpke-kdf-ids.csv",
        value_column="Value",
        name_column="KDF",
        our_files=("kdf.csv",),
        our_column="hpke_kdf",
        normalise="hex",
    ),
    Registry(
        key="hpke_aead",
        url="https://www.iana.org/assignments/hpke/hpke-aead-ids.csv",
        value_column="Value",
        name_column="AEAD",
        our_files=("aead.csv",),
        our_column="hpke_aead",
        normalise="hex",
    ),
    Registry(
        key="tls_sig",
        url="https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv",
        value_column="Value",
        name_column="Description",
        our_files=("signatures.csv",),
        our_column="tls_signaturescheme",
        normalise="hex",
    ),
    Registry(
        key="tls_group",
        url="https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv",
        value_column="Value",
        name_column="Description",
        our_files=("kem.csv",),
        our_column="tls_group",
    ),
    Registry(
        key="named_info",
        url="https://www.iana.org/assignments/named-information/hash-alg.csv",
        value_column="ID",
        name_column="Hash Name String",
        our_files=("hash.csv",),
        our_column="iana_named_info",
        notes="the file is hash-alg.csv, not named-information.csv as the page URL suggests",
    ),
)

# Columns we cite but cannot check here. Named explicitly so the report can say
# what it did not verify — an unstated gap reads as a clean bill of health.
UNCHECKED: dict[str, str] = {
    "x509_oid": "OIDs come from NIST CSOR and the ITU-T registry, not IANA",
    "spki_oid": "same as x509_oid",
    "multicodec_pub": "the multicodec table lives in a GitHub repository",
    "multicodec_priv": "same as multicodec_pub",
    "multihash": "same as multicodec_pub",
    "ssh_name": "SSH names are partly IANA, partly OpenSSH convention",
    "pgp_algo_id": "OpenPGP algorithm IDs need the RFC 9580 tables",
    "jose_alg": "the JOSE registry has a different shape; not yet wired up",
    "jose_enc": "same as jose_alg",
    "jwk_kty": "same as jose_alg",
    "jwk_crv": "same as jose_alg",
    "jwk_name": "key-params.csv is about field labels, not algorithm identifiers",
    "cose_label": "same as jwk_name",
}

# Rows describing a range or a hole rather than an algorithm. Matching on the
# name is necessary because "Unassigned" can carry a single number as readily as
# a range, and a number alone looks like a real assignment.
PLACEHOLDER_NAMES = re.compile(
    r"^(reserved|unassigned|deprecated|obsolete|private use|experimental)",
    re.IGNORECASE,
)

# Places where our name and the registry's name are both right and simply
# differ. Keyed by (registry, value); the string is why, and it has to be
# written out, because that is the difference between a documented divergence
# and an unnoticed error.
#
# This list exists so the name matcher can stay strict. Loosening the heuristic
# until these pass would also let a genuinely wrong citation through, and the
# whole point of the check is to catch exactly that.
ACCEPTED_DIVERGENCES: dict[tuple[str, str], str] = {
    ("cose_kty", "7"):
        "ML-DSA has no key type of its own: RFC 9964 gives it the generic AKP, "
        "which is the finding, not an error",
    ("cose_alg", "5"): "COSE names HMAC by tag size (HMAC 256/256), we by hash",
    ("cose_alg", "6"): "COSE names HMAC by tag size (HMAC 384/384), we by hash",
    ("cose_alg", "7"): "COSE names HMAC by tag size (HMAC 512/512), we by hash",
    ("cose_alg", "-40"):
        "COSE spells it 'RFC 8017 default parameters'; the default is SHA-1, "
        "which is the trap the map documents",
    ("cose_alg", "-41"): "COSE spells out RSAES-OAEP, we abbreviate",
    ("cose_alg", "-42"): "COSE spells out RSAES-OAEP, we abbreviate",
    ("hpke_kem", "0x0010"): "HPKE wraps the curve as DHKEM(P-256, HKDF-SHA256)",
    ("hpke_kem", "0x0011"): "HPKE wraps the curve as DHKEM(P-384, HKDF-SHA384)",
    ("hpke_kem", "0x0012"): "HPKE wraps the curve as DHKEM(P-521, HKDF-SHA512)",
    ("tls_group", "23"): "TLS uses SEC names (secp256r1) where we use NIST (P-256)",
    ("tls_group", "24"): "TLS uses SEC names (secp384r1) where we use NIST (P-384)",
    ("tls_group", "25"): "TLS uses SEC names (secp521r1) where we use NIST (P-521)",
    ("tls_sig", "0x0804"):
        "TLS splits PSS by key encoding: rsae for a PKCS#1 key, pss for a "
        "PSS-restricted one. 0x0809 is the other half",
}


@dataclass
class Finding:
    """One thing worth a human's attention."""

    kind: str
    """`missing`, `mismatch`, or `new`."""

    registry: str
    value: str
    ours: str = ""
    theirs: str = ""
    source_file: str = ""

    def __str__(self) -> str:
        match self.kind:
            case "missing":
                return (f"{self.registry} {self.value}: we cite {self.ours!r} "
                        f"({self.source_file}), registry has no such value")
            case "mismatch":
                return (f"{self.registry} {self.value}: we call it {self.ours!r} "
                        f"({self.source_file}), registry says {self.theirs!r}")
            case "new":
                return f"{self.registry} {self.value}: {self.theirs!r} — not in our map"
            case _:
                return f"{self.registry} {self.value}: {self.kind}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    registries_read: int = 0
    fetch_errors: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[Finding]:
        """Findings that mean the map is wrong, as opposed to incomplete."""
        return [f for f in self.findings if f.kind in ("missing", "mismatch")]

    @property
    def additions(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == "new"]


def fetch(session: niquests.Session | None, url: str, *, offline: bool) -> str:
    """Fetch a registry, caching the response.

    The cache lets a failing check be re-run without hammering IANA, and is what
    makes `--offline` possible. It is deliberately not time-limited: a stale
    cache producing a stale report is less harmful than a check that cannot run
    without network.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / (re.sub(r"[^A-Za-z0-9._-]", "_", url) + ".csv")

    if offline:
        if not cache_file.exists():
            raise FileNotFoundError(f"no cached copy of {url}")
        return cache_file.read_text(encoding="utf-8")

    assert session is not None, "a session is required when not offline"
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    body = response.text or ""

    # IANA answers a missing CSV with an HTML error page under a 200, so the
    # status code alone does not tell us whether this is data.
    if body.lstrip().lower().startswith("<!doctype"):
        raise ValueError("returned HTML, not CSV — the registry may have moved")

    cache_file.write_text(body, encoding="utf-8")
    return body


def make_session() -> niquests.Session:
    """One session for every registry.

    All ten registries live on www.iana.org, so a shared session means one
    connection and one TLS handshake instead of ten. Retries cover the
    transient 5xx that a run should not fail on.
    """
    session = niquests.Session(retries=3)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def normalise_value(raw: str, how: str) -> str | None:
    """Reduce a value to a comparable form.

    Returns None for ranges (`0x0001-0x000F`, `less than -65536`) and anything
    else that is not a single identifier — those describe registry structure,
    not algorithms.
    """
    text = raw.strip()
    if not text:
        return None

    # A leading minus is a sign, an interior one is a range: -65534 is a value,
    # 0x0001-0x000F is not.
    if "-" in text[1:] or text.lower().startswith("less than"):
        return None

    match how:
        case "hex":
            try:
                return f"0x{int(text, 16):04X}"
            except ValueError:
                return None
        case "int":
            try:
                return str(int(text, 0))
            except ValueError:
                return None
        case _:
            return text


def read_registry(
    reg: Registry, session: niquests.Session | None, *, offline: bool
) -> dict[str, tuple[str, str]]:
    """Registry as {normalised value: (name, description)}, placeholders dropped."""
    body = fetch(session, reg.url, offline=offline)
    rows = csv.DictReader(body.splitlines())

    if rows.fieldnames is None or reg.value_column not in rows.fieldnames:
        raise ValueError(
            f"expected a {reg.value_column!r} column, found {rows.fieldnames}"
        )

    entries: dict[str, tuple[str, str]] = {}
    for row in rows:
        name = (row.get(reg.name_column) or "").strip()
        if not name or PLACEHOLDER_NAMES.match(name):
            continue
        description = ""
        if reg.description_column:
            description = (row.get(reg.description_column) or "").strip()
        value = normalise_value(row.get(reg.value_column, ""), reg.normalise)
        if value is not None:
            entries[value] = (name, description)
    return entries


def read_our_values(reg: Registry) -> list[tuple[str, str, str]]:
    """Our citations as (normalised value, algorithm name, file).

    A cell may hold several values — COSE splits AES-CCM by nonce and tag
    length, so one algorithm cites `10/12/30/32`. Each is checked separately.
    """
    out: list[tuple[str, str, str]] = []
    for filename in reg.our_files:
        path = DATA_DIR / filename
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                cell = (row.get(reg.our_column) or "").strip()
                if not cell:
                    continue
                algorithm = (row.get("algorithm") or row.get("key_type") or "?").strip()
                for part in cell.split("/"):
                    value = normalise_value(part, reg.normalise)
                    if value is not None:
                        out.append((value, algorithm, filename))
    return out


def signature(text: str) -> str:
    """Strip a name down to its alphanumerics, upper-cased.

    `AES-256-GCM`, `A256GCM` and `AEAD_AES_256_GCM` all reduce to strings that
    contain one another; `ECDSA-P256-SHA256` and `ESP256` do not, which is why
    matching needs more than this alone.
    """
    return re.sub(r"[^A-Za-z0-9]", "", text).upper()


def names_agree(ours: str, theirs: str) -> bool:
    """Is the registry talking about the same algorithm we are?

    Deliberately loose, and it has to be: registries name things their own way.
    The AEAD registry prefixes everything with `AEAD_`, COSE compresses
    `AES-128-GCM` to `A128GCM`, HPKE wraps curves as `DHKEM(P-256, HKDF-SHA256)`,
    TLS lower-cases to `mldsa44`. A strict comparison reports a hundred
    differences that are all spelling, which trains the reader to ignore the
    report — and then the one real finding goes unseen too.

    What this catches is a value that moved to a *different algorithm*: the
    signatures then share neither containment nor a distinguishing number.

    A first version compared tokens split on punctuation and produced 39 false
    positives on the first run, because `A128GCM` is a single token and
    `AES-128-GCM` is three.
    """
    ours_sig, theirs_sig = signature(ours), signature(theirs)
    if not ours_sig or not theirs_sig:
        return True

    # Containment covers the common prefix/suffix cases: AES256GCM inside
    # AEADAES256GCM, X25519 inside DHKEMX25519HKDFSHA256.
    if ours_sig in theirs_sig or theirs_sig in ours_sig:
        return True

    # Otherwise fall back to the numbers, which survive every naming convention:
    # ECDSAP256SHA256 and ESP256 share 256, mldsa44 and MLDSA44 share 44. Two
    # names about the same algorithm rarely disagree on every digit.
    ours_digits = set(re.findall(r"\d+", ours_sig))
    theirs_digits = set(re.findall(r"\d+", theirs_sig))
    if ours_digits and theirs_digits and (ours_digits & theirs_digits):
        # Numbers alone are weak — AES-128-CCM and AES-128-GCM share 128 — so
        # require a shared letter run as well.
        ours_letters = set(re.findall(r"[A-Z]{2,}", ours_sig))
        theirs_letters = set(re.findall(r"[A-Z]{2,}", theirs_sig))
        if not ours_letters or not theirs_letters:
            return True
        return bool(ours_letters & theirs_letters) or any(
            a in b or b in a for a in ours_letters for b in theirs_letters
        )

    return False


def check_registry(
    reg: Registry, session: niquests.Session | None, *, offline: bool, find_new: bool
) -> list[Finding]:
    registry = read_registry(reg, session, offline=offline)
    findings: list[Finding] = []
    cited: set[str] = set()

    for value, algorithm, filename in read_our_values(reg):
        cited.add(value)
        if value not in registry:
            findings.append(Finding("missing", reg.key, value,
                                    ours=algorithm, source_file=filename))
            continue
        name, description = registry[value]
        # Either column may be the one that resembles our spelling: the short
        # name for A128GCM, the description for ESP256.
        if names_agree(algorithm, name) or (
            description and names_agree(algorithm, description)
        ):
            continue
        if (reg.key, value) in ACCEPTED_DIVERGENCES:
            continue
        theirs = f"{name} ({description})" if description else name
        findings.append(Finding("mismatch", reg.key, value, ours=algorithm,
                                theirs=theirs, source_file=filename))

    if find_new:
        for value, (name, description) in sorted(registry.items()):
            if value not in cited:
                theirs = f"{name} ({description})" if description else name
                findings.append(Finding("new", reg.key, value, theirs=theirs))

    return findings


def run(*, offline: bool, find_new: bool) -> Report:
    report = Report()
    session = None if offline else make_session()
    try:
        for reg in REGISTRIES:
            try:
                findings = check_registry(
                    reg, session, offline=offline, find_new=find_new
                )
            except (niquests.RequestException, ValueError, OSError) as exc:
                report.fetch_errors.append(f"{reg.key} ({reg.url}): {exc}")
                continue
            report.registries_read += 1
            report.checked += len(read_our_values(reg))
            report.findings.extend(findings)
    finally:
        if session is not None:
            session.close()
    return report


def findings_table(title: str, findings: list[Finding], *, style: str) -> Table:
    """Findings as a table.

    The `--new` listing runs past a hundred rows, and a wall of prose lines is
    something a reader skims rather than reads. Columns let the eye find the
    registry it cares about.
    """
    table = Table(title=title, title_style=style, title_justify="left",
                  header_style="bold", show_lines=False)
    table.add_column("Registry", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow", no_wrap=True)
    table.add_column("Ours")
    table.add_column("Registry says")
    table.add_column("File", style="dim", no_wrap=True)

    for finding in findings:
        table.add_row(
            finding.registry,
            finding.value,
            finding.ours or "—",
            finding.theirs or "—",
            finding.source_file or "—",
        )
    return table


@click.command()
@click.option("--new", "find_new", is_flag=True,
              help="Also list registry entries the map does not cite.")
@click.option("--offline", is_flag=True,
              help="Use cached responses instead of fetching.")
def main(find_new: bool, offline: bool) -> None:
    """Check IANA-sourced identifiers against the live registries."""
    with console.status("Reading registries..."):
        report = run(offline=offline, find_new=find_new)

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
            f"In the registries but not in the map ({len(report.additions)})",
            report.additions,
            style="bold yellow",
        ))
        console.print()

    console.print(
        f"Checked [bold]{report.checked}[/] citations across "
        f"[bold]{report.registries_read}/{len(REGISTRIES)}[/] registries."
    )

    if not report.problems and not report.fetch_errors:
        console.print("[bold green]No disagreements with IANA.[/]")
    if not find_new:
        console.print(
            "[dim]Run with --new to see what the registries have gained since.[/]"
        )

    console.print("\n[dim]Not checked here (other sources, other scripts):[/]")
    for column, why in sorted(UNCHECKED.items()):
        console.print(f"  [dim]{column}: {why}[/]")

    # Exit non-zero only for actual disagreements. New registry entries are
    # information, not failure: a CI job that breaks every time IANA adds a
    # codepoint gets muted, and then the real problems go unseen too.
    sys.exit(1 if (report.problems or report.fetch_errors) else 0)


if __name__ == "__main__":
    main()
