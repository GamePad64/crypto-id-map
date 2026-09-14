# scripts

Consistency checks for the map. One script per data source, because the sources
have nothing in common beyond the fact that we cite them.

| Script | Source | Covers |
|---|---|---|
| `check_iana.py` | IANA registries | COSE (algorithms, key types, curves), JOSE (alg/enc, kty, crv), IANA AEAD, HPKE (KEM/KDF/AEAD), TLS (SignatureScheme, Supported Groups), Named Information, SSH, OpenPGP, the PKIX OID arc |
| `check_multicodec.py` | multiformats table on GitHub | multicodec public and private key codes, multihash codes |
| `check_key_params.py` | IANA COSE and JOSE key parameter registries | the field labels inside COSE_Key and JWK |
| `check_oids.py` | nothing — structural only | OID syntax, arc membership, agreement across files |
| `check_cipher_suites.py` | IANA TLS cipher suite registry | suite numbers, exact names, the `Recommended` flag, references, and the kx/auth/cipher/hash decomposition against the name |
| `check_status.py` | the `Reference` and `Recommended` columns of every registry above | the `status` column |
| `check_references.py` | IETF datatracker | RFC numbers cited in prose: that they exist, and that an Informational RFC is not described as a standard |
| `check_shape.py` | nothing — structural only | column counts, headers, duplicate algorithm names. Needs no network, so it always runs |

`registrycheck.py` holds the comparison itself; the first two scripts supply
only what differs — where the data is and what its columns are called. The
others have their own shape and say why in their module docstrings.

## What is actually verified

The data was assembled by reading specifications, which is to say by a process
that can be confidently wrong. The scripts exist to make that checkable, so it
is worth being exact about how far they reach. Of 1573 non-empty cells:

| | cells | |
|---|---|---|
| compared against an external source | 1026 | 65% |
| structural, or cross-checked between files | 320 | 20% |
| not machine-verifiable | 227 | 14% |

The last row is the `notes` column and nothing else. It is prose: there is no
registry of assertions about algorithms, so `check_references.py` verifies the
RFC numbers inside a note while the claim wrapped around them rests on review.

That gap is not hypothetical. The map's one published factual error lived in a
note — two TLS codepoints described as having "held GOST under RFC 9189" and
been reallocated, neither half true — and it survived every check here, because
no check reads prose. It was caught by a reader asking a question. **If you are
relying on this map, the identifiers are checked and the prose is not.**

Coverage against a registry is also not the same as coverage against a
*registry*, and the difference matters:

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

uv run check_cipher_suites.py   # --new lists assigned suites the map omits
uv run check_status.py          # --offline only
uv run check_references.py      # asks the datatracker, no flags
uv run check_shape.py           # CSV structure, no network, no flags
```

At the last run, all eight clean: 318 IANA citations across 17 registries, 43
against the multicodec table, 57 field labels, 164 OIDs, 22 cipher suites, 188
status cells (38 more cite no machine-readable registry), 27 RFC citations in
prose across 14 documents, and 296 well-formed rows.

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

## Do the checks work?

A check that passes proves nothing until it has been shown capable of failing.
Each new script was tested by corrupting one cell at a time and confirming the
run turned red: a flipped `Recommended` flag, a suite name off by one hash, a
wrong key size, a wrong key exchange, a draft-only algorithm relabelled `rfc`,
an RFC-backed one relabelled `draft`, an invented status, a transposed RFC
number. All were caught.

The same technique found a bug in the checks themselves. The PKIX OID entry had
been reporting "no disagreements" since it was added — while reading **zero**
citations. The registry indexes its rows by the last arc alone (`37`), the map
writes OIDs in full (`1.3.6.1.5.5.7.6.37`), and nothing reconciled the two, so
every citation normalised away and the comparison ran over an empty set. A green
check that checks nothing is worse than a missing one, because it answers the
question you meant to ask. `Registry.arc` now strips the prefix, and the entry
went from 0 citations to 30.

Two things were learned from mutations that *weren't*:

- ML-DSA-44 relabelled `rfc` was not flagged, and correctly so — it is RFC 9964
  in COSE and a draft in TLS at once, which is why its real status is `mixed`.
  The mutation was a bad test, not a missed bug.
- An earlier `check_references.py` compared each RFC's title against its row's
  subject. Every finding was a false positive, so the comparison was removed
  rather than tuned. A check that cries wolf on correct data is worse than no
  check: it teaches the reader to skip the report, and then a real finding goes
  unseen too.
- `check_shape.py` first flagged any identifier appearing twice in a column. All
  22 findings were the map working as intended — one RSA-PSS OID serves six
  rows because PSS carries its hash in ASN.1 parameters, and `ES256` appears
  twice because TLS splits what JOSE keeps whole. Those collisions are the
  asymmetries the document exists to record, so the check was pointed the wrong
  way and was deleted.

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
