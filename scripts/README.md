# scripts

Consistency checks for the map. One script per data source, because the sources
have nothing in common beyond the fact that we cite them.

| Script | Source | Covers |
|---|---|---|
| `check_iana.py` | IANA registries | COSE (algorithms, key types, curves), JOSE (alg/enc, kty, crv), IANA AEAD, HPKE (KEM/KDF/AEAD), TLS (SignatureScheme, Supported Groups), Named Information, SSH, OpenPGP, the PKIX OID arc |
| `check_multicodec.py` | multiformats table on GitHub | multicodec public and private key codes, multihash codes |
| `check_key_params.py` | IANA COSE and JOSE key parameter registries | the field labels inside COSE_Key and JWK |
| `check_oids.py` | nothing — structural only | OID syntax, arc membership, agreement across files |

`registrycheck.py` holds the comparison itself; the first two scripts supply
only what differs — where the data is and what its columns are called. The
other two have their own shape and say why in their module docstrings.

**Every column in `data/` is now covered.** Not every one against a registry,
though, and the difference matters:

`check_oids.py` has no upstream to diff against. NIST CSOR publishes its arc as
HTML; the ANSI and RSADSI arcs are not published as data at all. Only the PKIX
arc (`1.3.6.1.5.5.7.6`, where the composite signature OIDs live) has a registry,
and `check_iana.py` covers it. So the OIDs get syntax, a known-arc test, and a
cross-file consistency check — which catches a mistyped digit, since a typo is
unlikely to be made identically twice — but nothing confirms that a well-formed
OID from a known arc is the *right* OID.

## Running

Python 3.14, dependencies managed by [uv](https://docs.astral.sh/uv/):

```
uv run check_iana.py            # verify what the map claims
uv run check_iana.py --new      # also list what the registries have gained
uv run check_iana.py --offline  # re-run against cached responses

uv run check_multicodec.py      # same flags, different source
uv run check_key_params.py      # same flags again
uv run check_oids.py            # structural only, no flags
```

At the last run: 242 citations across 17 IANA registries, 43 against the
multicodec table, 57 field labels, and 109 OIDs — every value in `data/`,
no disagreements.

Four dependencies, each earning its place: **niquests** (one HTTP/2 connection
for all ten registries instead of ten handshakes, with retries), **rich** (the
`--new` listing runs past a hundred rows — a table gets read, a wall of lines
gets skimmed), **platformdirs** (cache in the OS cache directory, so a checkout
stays clean), **click** (subcommands, once there is a second source to check).

Exit code is 1 on a disagreement or a fetch failure, 0 otherwise. New registry
entries do **not** fail the run: a check that breaks every time IANA assigns a
codepoint gets muted, and then the real findings go unseen too.

Responses are cached under the platform cache directory —
`~/.cache/crypto-id-map` on Linux — so a failing run can be re-examined without
fetching again. The cache has no expiry: a stale cache producing a stale report
is less harmful than a check that cannot run without network.

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

Traps worth knowing before you add the next one:

- **A missing CSV returns HTML under a 200 status.** The fetcher checks for a
  doctype rather than trusting the status code.
- **Filenames do not follow the page URL.** The AEAD registry page holds two
  tables and the algorithms live in `aead-parameters-2.csv`; Named Information
  serves `hash-alg.csv`, not `named-information.csv`; the SMI registry names its
  files after the OID arc itself. Read the page's download link rather than
  guessing.
- **Header cells may carry quotes or padding.** JOSE's key-type column is
  literally `"kty" Parameter Value`, quotes included; the multicodec table pads
  every column for alignment. Column lookup strips whitespace for this reason.
- **Scope the source to the file where a row means the same thing.** multicodec
  names *keys* while `signatures.csv` names *algorithms*: `0x1200` is "P-256
  public key", which serves ECDSA-P256-SHA256 and ECDH-P256 alike. Checking the
  signature file against it produced two dozen differences that all said the
  same true thing. Only `key-types.csv` is checked there.
