#!/usr/bin/env python3
"""Check the map's multicodec and multihash codes against the multiformats table.

Separate from the IANA check because the source is different in kind: a CSV in
a GitHub repository, governed by pull request rather than by an IETF process.
That difference matters for how much the codes can be trusted — every key code
is `draft` status, and `did:key` identifiers are derived from them, so a
codepoint revision changes identifiers that have already been published.

Usage:
    uv run check_multicodec.py            # report, exit 1 on any mismatch
    uv run check_multicodec.py --new      # also list codes we don't cite
    uv run check_multicodec.py --offline  # use the cached table
"""

from __future__ import annotations

import click

from registrycheck import Registry, console, report_and_exit, run

TABLE_URL = "https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv"

REGISTRIES: tuple[Registry, ...] = (
    # Only key-types.csv. The signature and KEM files cite the same codes, but
    # they name *algorithms* where multicodec names *keys*: 0x1200 is "P-256
    # public key", which serves ECDSA-P256-SHA256, ECDH-P256 and anything else
    # built on that curve. Checking those files here would report two dozen
    # differences that all say the same true thing — one key code, several
    # algorithms — and a report of expected noise is a report nobody reads.
    #
    # key-types.csv is where a row means a key, so that is where the codes are
    # checked against their source.
    Registry(
        key="multicodec_pub",
        url=TABLE_URL,
        value_column="code",
        name_column="name",
        description_column="description",
        our_files=("key-types.csv",),
        our_column="multicodec_pub",
        normalise="hex",
        strip_cells=True,
    ),
    Registry(
        key="multicodec_priv",
        url=TABLE_URL,
        value_column="code",
        name_column="name",
        description_column="description",
        our_files=("key-types.csv",),
        our_column="multicodec_priv",
        normalise="hex",
        strip_cells=True,
    ),
    Registry(
        key="multihash",
        url=TABLE_URL,
        value_column="code",
        name_column="name",
        description_column="description",
        our_files=("hash.csv",),
        our_column="multihash",
        normalise="hex",
        strip_cells=True,
    ),
)

UNCHECKED: dict[str, str] = {
    "everything else": "see check_iana.py",
}

ACCEPTED_DIVERGENCES: dict[tuple[str, str], str] = {
    ("multihash", "0x0012"):
        "multiformats names the family (sha2-256) where we name the algorithm "
        "(SHA-256)",
    ("multihash", "0x0013"): "same as 0x12: sha2-512 against SHA-512",
}


@click.command()
@click.option("--new", "find_new", is_flag=True,
              help="Also list table entries the map does not cite.")
@click.option("--offline", is_flag=True,
              help="Use the cached table instead of fetching.")
def main(find_new: bool, offline: bool) -> None:
    """Check multicodec and multihash codes against the multiformats table."""
    with console.status("Reading the multicodec table..."):
        report = run(REGISTRIES, ACCEPTED_DIVERGENCES,
                     offline=offline, find_new=find_new)

    if find_new:
        # The table carries every multiformat — CIDs, IPLD codecs, network
        # addresses — and listing all of them would bury the key codes that are
        # actually in scope here. Kept out of the default report on purpose.
        console.print(
            "[dim]Note: --new lists the entire multiformats table, most of "
            "which is out of scope for this map (CIDs, IPLD codecs, "
            "multiaddr protocols).[/]\n"
        )

    report_and_exit(report, UNCHECKED, find_new=find_new, source="multicodec")


if __name__ == "__main__":
    main()
