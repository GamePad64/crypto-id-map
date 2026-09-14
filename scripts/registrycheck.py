"""Shared machinery for checking the map against an upstream registry.

Every source answers the same two questions — is what we wrote still true, and
what has appeared since — so the comparison lives here and each source script
supplies only the part that differs: where the data is and what its columns are
called.

Nothing here edits the CSV files. A registry diff needs a human to decide
whether the map is wrong or the world moved, and an auto-fix would erase that
distinction.
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

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
    """One upstream registry and how to read it.

    Every registry has its own column names and its own idea of where the number
    lives — COSE puts `Name` first and `Value` second, HPKE the other way round,
    the AEAD registry splits its page into two tables so the data sits in a `-2`
    file, and multicodec pads its columns with spaces. None of that is
    guessable, so it is spelled out.
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

    strip_cells: bool = False
    """Strip whitespace inside cells. The multicodec table pads for alignment."""

    notes: str = ""


# Rows describing a range or a hole rather than an algorithm. Matching on the
# name is necessary because "Unassigned" can carry a single number as readily as
# a range, and a number alone looks like a real assignment.
PLACEHOLDER_NAMES = re.compile(
    r"^(reserved|unassigned|deprecated|obsolete|private use|experimental)",
    re.IGNORECASE,
)


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


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    registries_read: int = 0
    registries_total: int = 0
    fetch_errors: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[Finding]:
        """Findings that mean the map is wrong, as opposed to incomplete."""
        return [f for f in self.findings if f.kind in ("missing", "mismatch")]

    @property
    def additions(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == "new"]


def make_session() -> niquests.Session:
    """One session for every registry.

    Most sources put all their files on one host, so a shared session means one
    connection and one TLS handshake rather than one per registry. Retries cover
    the transient 5xx that a run should not fail on.
    """
    session = niquests.Session(retries=3)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def fetch(session: niquests.Session | None, url: str, *, offline: bool) -> str:
    """Fetch a registry, caching the response.

    The cache lets a failing check be re-run without hammering the source, and
    is what makes `--offline` possible. It is deliberately not time-limited: a
    stale cache producing a stale report is less harmful than a check that
    cannot run without network.
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
        case "oid":
            # Dotted decimal, compared as written. Leading zeros in an arc would
            # be a different OID, so no normalisation is wanted.
            return text if re.fullmatch(r"[0-9]+(\.[0-9]+)*", text) else None
        case _:
            return text


KEY_TYPE_PREFIX = re.compile(r"^(OKP|EC2|AKP|RSA|Symmetric)/")


# Spellings that mean the same thing across registries. Applied before the
# alphanumeric reduction, so `RSASSA-PSS-rsae-SHA384` and `rsa_pss_rsae_sha384`
# reduce to the same string instead of differing in the middle of one long run.
SYNONYMS = (
    ("RSASSA", "RSA"),
    ("ECDSA", "ES"),
)


def signature(text: str) -> str:
    """Strip a name down to its alphanumerics, upper-cased."""
    reduced = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    for long_form, short_form in SYNONYMS:
        reduced = reduced.replace(long_form, short_form)
    return reduced


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
    # `key-types.csv` writes `EC2/P-256` and `OKP/X25519` to say which COSE
    # `kty` a row belongs to. Against the COSE key-type registry the prefix *is*
    # the answer; against multicodec or SSH, which name the key alone
    # (`p256-pub`, `ssh-ed25519`), it is noise. Rather than teach the caller
    # which is which, try both forms and let either match.
    if KEY_TYPE_PREFIX.match(ours.strip()):
        stripped = KEY_TYPE_PREFIX.sub("", ours.strip())
        if names_agree(stripped, theirs):
            return True

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


def read_registry(
    reg: Registry, session: niquests.Session | None, *, offline: bool
) -> dict[str, tuple[str, str]]:
    """Registry as {normalised value: (name, description)}, placeholders dropped."""
    body = fetch(session, reg.url, offline=offline)
    rows = csv.DictReader(body.splitlines())

    if rows.fieldnames is None:
        raise ValueError("no header row")

    fieldnames = [f.strip() for f in rows.fieldnames]
    if reg.value_column not in fieldnames:
        raise ValueError(
            f"expected a {reg.value_column!r} column, found {fieldnames}"
        )

    def cell(row: dict[str, str | None], column: str) -> str:
        # The multicodec table pads columns with spaces for alignment, so the
        # header keys themselves carry trailing whitespace.
        for key, value in row.items():
            if key is not None and key.strip() == column:
                return (value or "").strip()
        return ""

    entries: dict[str, tuple[str, str]] = {}
    for row in rows:
        name = cell(row, reg.name_column)
        if not name or PLACEHOLDER_NAMES.match(name):
            continue
        description = cell(row, reg.description_column) if reg.description_column else ""
        value = normalise_value(cell(row, reg.value_column), reg.normalise)
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
                # Split on "/" for multi-valued cells, but not inside an OID.
                parts = [cell] if reg.normalise == "oid" else cell.split("/")
                for part in parts:
                    value = normalise_value(part, reg.normalise)
                    if value is not None:
                        out.append((value, algorithm, filename))
    return out


def check_registry(
    reg: Registry,
    session: niquests.Session | None,
    accepted: dict[tuple[str, str], str],
    *,
    offline: bool,
    find_new: bool,
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
        if (reg.key, value) in accepted:
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


def run(
    registries: tuple[Registry, ...],
    accepted: dict[tuple[str, str], str],
    *,
    offline: bool,
    find_new: bool,
) -> Report:
    report = Report(registries_total=len(registries))
    session = None if offline else make_session()
    try:
        for reg in registries:
            try:
                findings = check_registry(
                    reg, session, accepted, offline=offline, find_new=find_new
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


def report_and_exit(
    report: Report,
    unchecked: dict[str, str],
    *,
    find_new: bool,
    source: str,
) -> None:
    """Print the report and exit with a code CI can act on."""
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
        f"[bold]{report.registries_read}/{report.registries_total}[/] "
        f"{source} registries."
    )

    if not report.problems and not report.fetch_errors:
        console.print(f"[bold green]No disagreements with {source}.[/]")
    if not find_new:
        console.print(
            "[dim]Run with --new to see what the registries have gained since.[/]"
        )

    if unchecked:
        console.print("\n[dim]Not checked here (other sources, other scripts):[/]")
        for column, why in sorted(unchecked.items()):
            console.print(f"  [dim]{column}: {why}[/]")

    # Exit non-zero only for actual disagreements. New registry entries are
    # information, not failure: a CI job that breaks every time a registry gains
    # a codepoint gets muted, and then the real problems go unseen too.
    sys.exit(1 if (report.problems or report.fetch_errors) else 0)
