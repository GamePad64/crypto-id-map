# scripts

Consistency checks for the map. One script per data source, because the sources
have nothing in common beyond the fact that we cite them.

| Script | Source | Covers |
|---|---|---|
| `check_iana.py` | IANA registries | COSE (algorithms, key types, curves), IANA AEAD, HPKE (KEM/KDF/AEAD), TLS (SignatureScheme, Supported Groups), Named Information |

Not yet written, and named in `check_iana.py`'s output so the gap stays
visible: OIDs (NIST CSOR and ITU-T), multicodec (a GitHub table), SSH names
(part IANA, part OpenSSH convention), OpenPGP algorithm IDs, and the JOSE
registry.

## Running

No dependencies beyond the standard library. Python 3.14.

```
python3 check_iana.py            # verify what the map claims
python3 check_iana.py --new      # also list what the registries have gained
python3 check_iana.py --offline  # re-run against cached responses
```

Exit code is 1 on a disagreement or a fetch failure, 0 otherwise. New registry
entries do **not** fail the run: a check that breaks every time IANA assigns a
codepoint gets muted, and then the real findings go unseen too.

Responses are cached under `.cache/` (git-ignored) so a failing run can be
re-examined without fetching again.

## What the check actually does

For every identifier the map cites, confirm the registry still has that value
and still uses it for the algorithm we say. Then, with `--new`, list registry
entries the map does not mention.

Names are compared loosely, and they have to be: the AEAD registry prefixes
everything with `AEAD_`, COSE compresses `AES-128-GCM` to `A128GCM`, HPKE wraps
curves as `DHKEM(P-256, HKDF-SHA256)`, TLS lower-cases to `mldsa44`. Reconciling
those spellings is the map's whole purpose, so a strict match would flag a
hundred differences that are all cosmetic — and a report full of noise is a
report nobody reads.

Where a name genuinely differs and both are right — TLS calling P-256
`secp256r1`, COSE naming HMAC by tag length — the pair is listed in
`ACCEPTED_DIVERGENCES` with the reason written out. That list is what lets the
matcher stay strict: loosening the heuristic until those passed would also let a
wrong citation through.

## Adding a registry

Append a `Registry` entry. The fields exist because nothing about these files is
guessable:

- `value_column` / `name_column` — COSE puts `Name` first and `Value` second,
  HPKE the reverse.
- `description_column` — optional. COSE names `-9` as `ESP256` and describes it
  as "ECDSA using P-256 curve and SHA-256"; the map uses the descriptive form,
  so matching against either column avoids a false positive.
- `normalise` — `int` or `hex`, since HPKE and TLS write `0x0020` where COSE
  writes `-8`.
- `our_files` / `our_column` — where the map cites this registry.

Two traps worth knowing before you add the next one:

- **A missing CSV returns HTML under a 200 status.** The fetcher checks for a
  doctype rather than trusting the status code.
- **Filenames do not follow the page URL.** The AEAD registry page holds two
  tables and the algorithms live in `aead-parameters-2.csv`; Named Information
  serves `hash-alg.csv`, not `named-information.csv`. Read the page's download
  link rather than guessing.
