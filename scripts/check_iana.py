#!/usr/bin/env python3
"""Check the map's IANA-sourced identifiers against the live registries.

Two questions, both of which the map goes stale on:

1. **Is what we wrote still true?** A value we cite must exist in the registry
   and name the algorithm we think it names.
2. **What appeared since?** Registries gain entries continuously — ML-DSA
   entered COSE in 2026, composite signature OIDs were allocated in 2025 — and a
   reference that silently misses them is worse than no reference.

Covers everything IANA publishes as CSV: COSE, JOSE, the AEAD registry, HPKE,
TLS, Named Information, SSH, OpenPGP, and the PKIX arc of the SMI registry.
multicodec has its own script; NIST's OID arc has none, because it is published
only as HTML.

Usage:
    uv run check_iana.py            # report, exit 1 on any mismatch
    uv run check_iana.py --new      # also list registry entries we don't cite
    uv run check_iana.py --offline  # use cached responses, no network
"""

from __future__ import annotations

import click

from registrycheck import Registry, console, report_and_exit, run

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
    # JOSE is four registries because the identifiers are strings living in
    # different fields: `alg` and `enc` share one table, `kty` and `crv` have
    # their own.
    Registry(
        key="jose_alg",
        url="https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv",
        value_column="Algorithm Name",
        name_column="Algorithm Name",
        description_column="Algorithm Description",
        our_files=("signatures.csv", "kdf.csv", "mac.csv", "keywrap.csv"),
        our_column="jose_alg",
        normalise="str",
    ),
    Registry(
        key="jose_enc",
        url="https://www.iana.org/assignments/jose/web-signature-encryption-algorithms.csv",
        value_column="Algorithm Name",
        name_column="Algorithm Name",
        description_column="Algorithm Description",
        our_files=("aead.csv",),
        our_column="jose_enc",
        normalise="str",
        notes="`alg` and `enc` share one registry, distinguished by the usage column",
    ),
    Registry(
        key="jwk_kty",
        url="https://www.iana.org/assignments/jose/web-key-types.csv",
        value_column='"kty" Parameter Value',
        name_column='"kty" Parameter Value',
        description_column="Key Type Description",
        our_files=("key-types.csv",),
        our_column="jwk_kty",
        normalise="str",
    ),
    Registry(
        key="jwk_crv",
        url="https://www.iana.org/assignments/jose/web-key-elliptic-curve.csv",
        value_column="Curve Name",
        name_column="Curve Name",
        description_column="Curve Description",
        our_files=("key-types.csv", "kem.csv"),
        our_column="jwk_crv",
        normalise="str",
    ),
    Registry(
        key="ssh_name",
        url="https://www.iana.org/assignments/ssh-parameters/ssh-parameters-19.csv",
        value_column="Public Key Algorithm Name",
        name_column="Public Key Algorithm Name",
        our_files=("key-types.csv",),
        our_column="ssh_name",
        normalise="str",
        notes="IANA covers the registered names; OpenSSH ships others by convention",
    ),
    Registry(
        key="pgp_algo_id",
        url="https://www.iana.org/assignments/openpgp/openpgp-public-key-algorithms.csv",
        value_column="ID",
        name_column="Algorithm",
        our_files=("key-types.csv",),
        our_column="pgp_algo_id",
    ),
    # Only the PKIX arc. NIST's own arc (2.16.840.1.101.3.4.*) is published as
    # HTML with no machine-readable form, so those OIDs stay hand-checked.
    Registry(
        key="pkix_oid",
        url="https://www.iana.org/assignments/smi-numbers/smi-numbers-1.3.6.1.5.5.7.6.csv",
        value_column="Decimal",
        name_column="Description",
        our_files=("signatures.csv",),
        our_column="x509_oid",
        notes="composite signature OIDs; the file is named after the arc itself",
    ),
)

# Columns we cite but cannot check here. Named explicitly so the report can say
# what it did not verify — an unstated gap reads as a clean bill of health.
UNCHECKED: dict[str, str] = {
    "x509_oid (NIST arc)":
        "2.16.840.1.101.3.4.* is published by NIST CSOR as HTML only; the PKIX "
        "arc above is checked, the NIST one is not",
    "spki_oid": "same arcs as x509_oid",
    "multicodec_pub": "see check_multicodec.py",
    "multicodec_priv": "see check_multicodec.py",
    "multihash": "see check_multicodec.py",
    "jwk_name": "key-params.csv is about field labels, not algorithm identifiers",
    "cose_label": "same as jwk_name",
}

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
    ("jose_alg", "HS256"): "JOSE abbreviates HMAC-SHA256 to HS256",
    ("jose_alg", "HS384"): "JOSE abbreviates HMAC-SHA384 to HS384",
    ("jose_alg", "HS512"): "JOSE abbreviates HMAC-SHA512 to HS512",
    ("jwk_kty", "AKP"):
        "the JWK counterpart of COSE kty 7: ML-DSA has no key type of its own",
    ("pgp_algo_id", "18"):
        "OpenPGP identifies the algorithm, not the curve — one ECDH id covers "
        "every curve, which lives in the key material instead",
    ("pgp_algo_id", "19"):
        "one ECDSA id covers every curve, for the same reason as 18",
    ("pgp_algo_id", "22"):
        "EdDSALegacy: the MPI-encoded Ed25519, distinct from id 27 and giving "
        "the same key a different fingerprint",
}


@click.command()
@click.option("--new", "find_new", is_flag=True,
              help="Also list registry entries the map does not cite.")
@click.option("--offline", is_flag=True,
              help="Use cached responses instead of fetching.")
def main(find_new: bool, offline: bool) -> None:
    """Check IANA-sourced identifiers against the live registries."""
    with console.status("Reading registries..."):
        report = run(REGISTRIES, ACCEPTED_DIVERGENCES,
                     offline=offline, find_new=find_new)
    report_and_exit(report, UNCHECKED, find_new=find_new, source="IANA")


if __name__ == "__main__":
    main()
