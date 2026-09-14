# crypto-id-map

**The same algorithm carries different identifiers in COSE, JOSE, TLS, HPKE, the
IANA AEAD registry, X.509 and multicodec** — and some algorithms exist in one
registry while being conspicuously absent from its sibling. This repository maps
them.

Ten CSV files, one per axis, plus the prose that tables cannot carry: where the
gaps are, where two registries disagree about the same algorithm, and which
mappings look one-to-one but are not.

Verified against IANA registries and RFCs in **September 2026**. Registries
move — ML-DSA entered COSE in 2026, composite signature OIDs were allocated in
2025 — so treat the date as part of the data.

Licensed [CC-BY-4.0](LICENSE): use it anywhere, keep the attribution so the
lineage stays traceable.

## What this is, and what it is not

**This is a map, not a registry.** It assigns no identifiers of its own and
never will. The moment a document starts handing out values it becomes a
registry, with the permanent obligations that follow: an assigned number can
never be reused, the table must stay reachable for as long as data referencing
it exists, and someone must run a process for registration and disputes. A map
carries none of that and therefore needs nobody's authority to exist.

**This is not a standard, nor a bid to become one.** Where an algorithm is
missing from a registry that ought to have it, the right move is to register it
there — not to invent a private value. The Gaps section exists to make those
places visible.

## Why no single registry exists

Registries were created **for protocols**, not for algorithms. TLS registered
cipher suites because TLS negotiates a bundle during the handshake. COSE and
JOSE registered algorithms for signed objects, each in its own notation. HPKE
registered three independent axes because there they genuinely combine freely.
X.509 uses OIDs because ASN.1 demands them.

Each working group owns its protocol, and its mandate stops at that boundary.
There is no "responsible for cross-registry coherence" role in the IETF, and the
problem only bites those who use several registries at once.

Three unification attempts exist, and all ran into the same wall:

- **OIDs** — the ISO idea of one hierarchical namespace for everything. It
  failed on ergonomics, not on design: ASN.1 encoding, 10–15 byte values,
  registration through national bodies. Yet OIDs still carry identifiers that
  exist nowhere else — composite signatures among them.
- **multicodec** — the modern attempt, with compact encoding and open
  registration. Open registration is exactly what disqualifies it for normative
  use: no vetting, no stability guarantee, so the IETF will not cite it.
- **COSE/JOSE** — the closest, covering both signatures and encryption. But they
  are bound to their object formats and exclude anything those formats do not
  use.

The post-quantum transition made the divergence visible: **hybrids** are
combinations of algorithms from different families, and they need identifiers.
Composite signatures got OIDs — 18 of them, plus 12 more for composite KEMs —
because PKIX cannot function without one. They got nothing anywhere else: no
COSE, no JOSE, no TLS, no multicodec. Thirty algorithms that exist in exactly
one namespace.

## Prior art

No complete map exists — checked against IANA, the IETF, multiformats,
Blockchain Commons and curated resource lists. The COSE↔JOSE pair is the only
one anyone has mapped systematically, and only inside the IETF:

| Document | Coverage |
|---|---|
| [RFC 8812](https://www.rfc-editor.org/rfc/rfc8812.html) | COSE↔JOSE, WebAuthn algorithms |
| [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) | COSE↔JOSE, fully-specified algorithms; deprecates polymorphic EdDSA and ES256 |
| [RFC 9964](https://www.rfc-editor.org/info/rfc9964/) | COSE↔JOSE, ML-DSA |
| [NIST CSOR](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration) | OIDs only |
| [multicodec table.csv](https://github.com/multiformats/multicodec/blob/master/table.csv) | multicodec only |

**Nobody maps IANA identifiers to OIDs to multicodec.**

## The data

Machine-readable, one file per axis. Empty field means the algorithm is absent
from that registry.

| File | Axis |
|---|---|
| [`data/signatures.csv`](data/signatures.csv) | signatures |
| [`data/kem.csv`](data/kem.csv) | key agreement and KEMs |
| [`data/aead.csv`](data/aead.csv) | authenticated encryption |
| [`data/hash.csv`](data/hash.csv) | hashes |
| [`data/kdf.csv`](data/kdf.csv) | key derivation |
| [`data/mac.csv`](data/mac.csv) | message authentication |
| [`data/keywrap.csv`](data/keywrap.csv) | key wrap and key encryption |
| [`data/cipher.csv`](data/cipher.csv) | unauthenticated ciphers |
| [`data/key-types.csv`](data/key-types.csv) | key type identifiers |
| [`data/key-params.csv`](data/key-params.csv) | field labels inside COSE_Key and JWK |
| [`data/tls-cipher-suites.csv`](data/tls-cipher-suites.csv) | cipher suites, decomposed — see below |

The `status` column says how solid the identifier is: `rfc` — backed by a
published RFC; `draft` — draft only; `early-alloc` — early IANA allocation, so
the value is stable although the document has not shipped; `mixed` — solid in
some registries and draft in others; `obsolete` — dead, do not implement;
`none` — no identifier anywhere; `other` — registered from a non-IETF
specification.

## A worked example

This map came out of designing a storage format that needed a post-quantum
suite. Picking one turned into an exercise in registry archaeology, and the
three obstacles are typical rather than exotic:

| Role | Algorithm | Registry that has it | Value |
|---|---|---|---|
| Signature | composite MLDSA65-Ed25519-SHA512 | OID (IANA SMI) | `1.3.6.1.5.5.7.6.48` |
| KEM | X-Wing (X25519 + ML-KEM-768) | HPKE KEM | `0x647A` |
| KDF | HKDF-SHA256 | HPKE KDF | `0x0001` |
| AEAD, content | XChaCha20-Poly1305 | IANA AEAD | 38 |
| AEAD, metadata | AES_SIV_CMAC_512 | IANA AEAD | 17 |
| Hash | SHA-256 | COSE | −16 |

- **The composite signature has an OID and nothing else** — no COSE, no TLS.
  The identifier travels as an OID by necessity, not by choice.
- **XChaCha20 and AES-SIV live only in the IANA AEAD registry.** Citing COSE,
  the customary registry for CBOR work, would find neither.
- **X-Wing exists in HPKE and not in TLS**, so referencing it commits to the
  HPKE side of the post-quantum hybrid split.

Six identifiers, four registries, and no single place to look them up. Hence
this document.

## Key representation: a different kind of divergence

The algorithm axes disagree on **numbers** — the same AES-GCM carries different
integers in different registries, but it is one algorithm. Key representation
disagrees on **structure**, and the translations are not always reversible.

**Two philosophies of identification.** COSE and JOSE put the parameter set in
`crv` alongside a broad `kty`. The post-quantum additions broke even that:
RFC 9964 introduced `AKP` (COSE `kty` 7, JWK `"AKP"`) as a generic
algorithm-key-pair type carrying **no** parameter information, which makes `alg`
mandatory on every such key. Multicodec, SPKI and SSH went the opposite way —
one identifier per parameter set, so ML-DSA-44, -65 and -87 each get their own.

**ML-KEM has no COSE or JWK key type at all.** Encapsulation keys are expressible
only as SPKI or multicodec. A format that wants a post-quantum KEM key inside a
CBOR object has nothing to name it with.

**HSS-LMS is COSE-only** (`kty` 5); XMSS is effectively unrepresented outside
RFC 8391's own encoding.

### Six containers, one key

The same Ed25519 public key:

| Container | Form |
|---|---|
| COSE_Key | CBOR map `{1:1, -1:6, -2:h'…32 bytes…'}`, raw bytes |
| JWK | `{"kty":"OKP","crv":"Ed25519","x":"…"}`, base64url unpadded |
| SPKI/DER | `SEQUENCE { AlgorithmIdentifier{OID, params ABSENT}, BIT STRING }` |
| PEM | the DER above, padded base64, 64-column wrapped, BEGIN/END lines |
| SSH wire | `string "ssh-ed25519" ‖ string <32 bytes>`, then base64 |
| did:key | `z` + base58btc( varint(multicodec) ‖ raw bytes ) |

`did:key` prefixes fall out of the varint and are worth recognising on sight:
Ed25519 → `z6Mk…`, X25519 → `z6LS…`, secp256k1 → `zQ3s…`, P-256 → `zDn…`,
P-384 → `z82…`, RSA → `z4MX…`.

Two `did:key` irregularities: the NIST curves are stored **compressed**
(33/49/67 bytes), and RSA is a PKCS#1 `RSAPublicKey` DER rather than SPKI —
unlike every other type in the method.

### Thumbprints: six schemes, no two agree

| Scheme | Preimage | Hash | Output |
|---|---|---|---|
| JWK Thumbprint (RFC 7638) | JSON of required members only, names sorted by code point, no whitespace | SHA-256 | 32 B, base64url |
| COSE Key Thumbprint (RFC 9679) | CBOR map of required labels only, RFC 8949 §4.2.1 deterministic | SHA-256 | 32 B, raw |
| X.509 SKI method 1 | the `subjectPublicKey` BIT STRING **value** only | SHA-1 | 20 B |
| X.509 SKI method 2 | same | SHA-1 truncated | 8 B, `0100` ‖ low 60 bits |
| SSH fingerprint | the decoded SSH wire blob, **including** the algorithm-name string | SHA-256 | base64, `=` stripped |
| PGP v4 | `0x99` ‖ 2-octet length ‖ packet body | SHA-1 | 20 B hex |
| PGP v6 | `0x9b` ‖ 4-octet length ‖ body | SHA-256 | 32 B hex |

**No two of these produce the same bytes for the same key.** RFC 9679 states it
outright: `ckt` and `jkt` differ even when the key material is identical, because
one hashes canonical CBOR and the other canonical JSON. Same hash function, same
conceptual field set, different input.

The practical consequence: **"key fingerprint" is not a portable concept.** A
system that stores a fingerprint must record which scheme produced it, and
cannot compare fingerprints across ecosystems. A format inventing its own — for
example `SHA-256` over a fixed byte concatenation — is not doing anything unusual;
it is joining a field where everyone already disagrees.

## Cipher suites: the file that maps to nothing

`tls-cipher-suites.csv` is shaped differently from every other file here,
because a cipher suite is not an algorithm identifier — it is a **composition**.
`TLS_AES_128_GCM_SHA256` has no counterpart in COSE or as an OID; its *parts*
do, and they are already in the other files. So this file decomposes instead of
mapping: key exchange, authentication, cipher and mode, key size, PRF hash.

It is here because the history is the clearest argument in this document for why
per-axis registries won.

**TLS 1.2 put four things in one number** — key exchange, authentication, cipher
and MAC. The registry grew to **356 assigned suites, of which 14 are marked
Recommended=Y: 3.9%**. Combinatorics did that: adding one cipher required a new
codepoint for every combination it could appear in, and almost none of them were
ever deployed.

**TLS 1.3 abandoned the approach.** A suite now names only the symmetric half,
while signatures and key exchange are negotiated through their own registries —
the same registries this map covers. Five suites replaced hundreds. HPKE was
designed per-axis from the start, and this map is organised the same way.

**A national standard replaces the whole symmetric layer.** The GOST suites
(`0xC100`–`0xC106`) are the clearest case: TLS 1.3 with GOST does **not** use
`TLS_AES_128_GCM_SHA256` or its siblings. It defines its own suites over
Kuznyechik and Magma in MGM mode, with GOST R 34.11-2012 as the hash. So the
TLS 1.3 design — a suite names only the AEAD and the hash, everything else is
negotiated separately — holds structurally while every algorithm inside is
replaced. The `_L` and `_S` variants differ in how much key material is used
before rekeying, not in the algorithm.

Two things in the file that mislead on sight:

- **The hash in a TLS 1.3 suite name is the PRF, not a MAC.** GCM and
  ChaCha20-Poly1305 authenticate by themselves; `SHA384` in
  `TLS_AES_256_GCM_SHA384` names the HKDF hash used for key schedule.
- **`TLS_AES_128_CCM_8_SHA256` (`0x1305`) is the one TLS 1.3 suite not
  recommended.** The `_8` truncates the authentication tag to 8 bytes, dropping
  forgery resistance to about 2⁶⁴ — defensible on constrained links, not in
  general.

## Gaps: widely used, registered nowhere

| Algorithm | Where it is used | Only identifier anywhere |
|---|---|---|
| **Argon2id** | the OWASP default recommendation for password storage; libsodium | none. PHC string `$argon2id$`. RFC 9106 states verbatim that it has no IANA actions |
| **bcrypt** | probably the most widely deployed password hash in production | none. The `$2a$` / `$2b$` prefix |
| **BLAKE3** | content addressing, fast hashing | multicodec `0x1e` — a draft, non-IANA, and a *multihash* code rather than an algorithm identifier |
| **scrypt** | Tarsnap, Litecoin, assorted KDF uses | an OID, and that on the GnuPG private-enterprise arc |
| **BLAKE2b** | libsodium default, Argon2 internals, IPFS | a name string in Named Information with no numeric id; multihash `0xb220` |

| **AES-CMAC** | RFC 4493; widely used for MAC where AES hardware exists | none — no OID in the NIST aes arc, no COSE, no JOSE |
| **Poly1305 standalone** | used as a bare MAC in several designs | none — identifiers exist only for the ChaCha20-Poly1305 AEAD |
| **ChaCha20 without Poly1305** | stream cipher in its own right | none — only the AEAD combination is registered |

The pattern: **IANA registers what IETF protocols need.** Password hashing and
content addressing are not IETF territory, so their algorithms stay outside no
matter how widely deployed they are. There is no IANA registry for password
hashing at all.

The same logic explains the MAC and cipher gaps: registries cover what protocols
**compose**, not what libraries **expose**. A protocol picks an AEAD, so the AEAD
gets a number; the stream cipher and the MAC inside it do not, even though every
library ships them separately.

## Asymmetries: present here, missing there

- **SLH-DSA** has full OID and multicodec coverage and a TLS draft, and **zero
  presence in COSE or JOSE**. A NIST standard unavailable to signed CBOR.
- **XChaCha20-Poly1305 and AES-SIV** exist only in the IANA AEAD registry —
  nothing in COSE, nothing in HPKE. Anyone needing either must cite that
  registry rather than the customary COSE.
- **JOSE has no HKDF whatsoever.** It uses Concat KDF (NIST SP 800-56A) for
  ECDH-ES. This is an algorithmic incompatibility with COSE, not a naming
  difference: COSE `-10` has no JOSE counterpart to translate into.
- **SHA3 is absent from COSE** while present in Named Information, X.509 and
  multihash — even though SHAKE, its sibling from the same standard, is in COSE.
- **JOSE lacks the fully-specified ECDSA identifiers** (`ESP256`, `ESP384`) that
  RFC 9864 added to COSE. The polymorphic `ES256` remains the only JOSE spelling.
- **AES-192-GCM** is in COSE, JOSE and X.509 but not in the IANA AEAD registry.
- **Post-quantum hybrids diverged the most.** TLS and HPKE each invented their
  own and they do not coincide: X-Wing exists in HPKE and not in TLS,
  X25519MLKEM768 exists in TLS and not in HPKE. A format needing a hybrid must
  pick a side.

## Footguns

Collected the hard way. Each of these breaks a naive one-to-one mapping.

**The same integer means different things.** There is no shared numbering
discipline across registries:

| Value | COSE | IANA AEAD | HPKE AEAD | HPKE KDF |
|---|---|---|---|---|
| `1` | AES-128-GCM | AES-128-GCM | AES-128-GCM | HKDF-SHA256 |
| `2` | AES-192-GCM | AES-256-GCM | AES-256-GCM | HKDF-SHA384 |
| `3` | AES-256-GCM | AES-128-CCM | ChaCha20-Poly1305 | HKDF-SHA512 |

`3` is the sharpest: A256GCM in COSE, AES-128-CCM in the AEAD registry,
ChaCha20-Poly1305 in HPKE. Never store a bare integer without recording which
registry it came from.

**Names that mislead.** `AEAD_AES_SIV_CMAC_256` is **AES-128** internally.
RFC 5297 names the variants by *total* key length, which then splits in half:
256 bits total means two 128-bit halves. For AES-256 strength you need
`AEAD_AES_SIV_CMAC_512` (17) with a 64-byte key. Rust's `aes-siv` crate follows
the same convention, so `Aes256SivAead` is the right type and it maps to 17, not
15.

**Dead values still in circulation.**

- Composite signature OIDs moved arcs. Draft −00 used the Entrust arc
  `2.16.840.1.114027.80.8.1.{3,10}`; those are dead. The live values are
  `1.3.6.1.5.5.7.6.37`–`.54`, and the registry now cites them to
  `RFC-ietf-lamps-pq-composite-sigs-19` — an approved document waiting on an RFC
  number, not a draft that might still move. The composite *KEM* OIDs
  (`.55`–`.66`) are a step behind, still citing
  `draft-ietf-lamps-pq-composite-kem-10`.
- `X25519Kyber768Draft00` (TLS group `25497`, HPKE KEM `0x0030`) is
  pre-standardisation Kyber, not ML-KEM. Shipped widely, now obsolete.

**Registries that split where others do not.**

- TLS splits RSASSA-PSS into six values where PKIX has one OID, and the split
  encodes a property of the **certificate**, not of the signature. Both sign
  identically; `rsae` means the key's SPKI says `rsaEncryption`
  (`1.2.840.113549.1.1.1`) — a general RSA key that may also produce PKCS#1 v1.5
  signatures — while `pss` means the SPKI itself says `id-RSASSA-PSS`
  (`…1.1.10`), a key restricted to PSS. A peer advertises both because it is
  stating which certificate *shapes* it accepts.

  The consequence for a map: **the OID column cannot disambiguate them.** Both
  rows carry `1.2.840.113549.1.1.10` as the signature OID, and the
  discriminator lives in a different field of a different structure. The hash is
  not in the OID either — it sits in the `RSASSA-PSS-params`, which is why one
  OID serves all three hashes while PKCS#1 v1.5 mints a separate OID per hash
  (`…1.1.11/.12/.13`). Three registries, three granularities.
- COSE splits AES-CCM by nonce and tag length — eight values (`10`–`13`,
  `30`–`33`) against two in the AEAD registry (`3`, `4`). There is no 1:1
  mapping in either direction.

**Deprecated but still common.** RFC 9864 deprecated the polymorphic COSE
identifiers — `-8` (EdDSA), `-7` (ES256), `-35`, `-36` — because the curve comes
from the key rather than the algorithm identifier, which makes the signature
algorithm ambiguous on its own. The fully-specified replacements are `-19`
(Ed25519), `-9` (ESP256), `-51`, `-52`. Deployed software still emits the old
ones, and JOSE never got the replacements at all.

**Named Information stops numbering.** Numeric ids in that registry end at 12.
Everything added later — BLAKE2, KT128/KT256 — exists as a name string only, so
code expecting an integer will not find one.

**One TLS registry shows through into another.** TLS 1.2 named signatures in
`SignatureAlgorithm` — a one-byte value paired with a one-byte hash. TLS 1.3
replaced that with the 16-bit `SignatureScheme`, whose low byte is the old
`hash‖signature` pair. So a TLS 1.2 allocation appears in the TLS 1.3 registry
at a computable address, and the two registries overlap rather than sit beside
each other.

GOST is where this surfaces. RFC 9189 assigns `SignatureAlgorithm` 64 and 65,
which show through at `0x0840` and `0x0841`, and the RFC reserved those to stop
anyone else being allocated them. IANA's own note admits the values "were
allocated from the Reserved state due to a misunderstanding of the difference
between Reserved and Unallocated that went undetected for a long time", and that
new allocations belong in `SignatureScheme`.

Reading `0x0840` as a GOST signature scheme is therefore wrong twice over: it is
a blocking reservation, not an assignment, and the real GOST schemes are
`0x0709`–`0x070F` from RFC 9367. (This map said otherwise until it was
checked — which is the argument for checking.)

**`RSA-OAEP` in JOSE means SHA-1**, and JOSE rates it `Recommended+` while the
safer `RSA-OAEP-256` is merely `Optional`. Reading the bare name as "OAEP with
modern defaults" selects a deprecated hash with the registry's encouragement.
COSE is honest about it: `-40` is spelled "RSAES-OAEP w/ RFC 8017 default
parameters" and documented as SHA-1.

Worse for mapping: **every OAEP variant shares one OID**
(`1.2.840.113549.1.1.7`), with the hash carried in ASN.1 parameters. An
OID→algorithm table silently loses the hash choice. And `RSA-OAEP-384` /
`RSA-OAEP-512` come from W3C WebCrypto rather than RFC 7518 — a different change
controller inside the same registry.

**Sign loss turns key wrap into content encryption.** COSE key-wrap identifiers
are negative (`-3`/`-4`/`-5` = A128/192/256KW) while AEAD identifiers are
positive (`1`/`2`/`3` = A128/192/256GCM). Drop the sign — an unsigned
deserialiser, a JSON round-trip, a stray `abs()` — and `A128KW` (`-3`) reads as
`A256GCM` (`+3`). Enforce signed CBOR integers and reject positives where a
negative is expected.

Adjacent low negatives make the same class of bug worse: `-6` is `direct` ("use
the content key as-is") and `-7` is `ES256`. An off-by-one converts a key
handling instruction into a signature algorithm.

**COSE `AES-MAC` is CBC-MAC, not CMAC.** RFC 9053 defines it as raw AES-CBC with
a zero IV, keeping the last block. Plain CBC-MAC is existentially forgeable over
variable-length messages: given tags for M1 and M2 you can forge one for their
concatenation. CMAC's subkey step exists to fix exactly that, and COSE gets away
without it only because it always authenticates a fixed-shape `MAC_structure`.

Two consequences: **never reuse an AES-MAC key outside that structure**, and an
implementer who reads "AES-MAC" and reaches for an AES-CMAC library produces
tags that do not verify. AES-CMAC itself has **no identifier anywhere** — no
COSE, no JOSE, no OID in the NIST aes arc.

**COSE `AES-MAC` values are non-contiguous.** `14` and `15` are the 64-bit tag
variants, `25` and `26` the 128-bit ones; `16`–`23` belong to unrelated
algorithms. Iterating a range will pick up the wrong thing.

**KMAC's two OID pairs are not duplicates.** RFC 8702 registered
`id-KMACWithSHAKE128` (`…3.4.2.19`) and `…256` (`.20`) as the **MAC** for CMS,
with optional parameters defaulting to 256/512-bit output and empty
customisation. RFC 9688 later registered `id-kmac128` (`.21`) and `id-kmac256`
(`.22`) for **KMAC used as a KDF**. Use `.19`/`.20` when you mean a MAC and
`.21`/`.22` when following RFC 9688; state which RFC you follow, because they
are not interchangeable. Neither COSE nor JOSE has KMAC at all.

**`RSA1_5` was deliberately never given a COSE value.** Its absence is a
decision, not an oversight — do not allocate a private value to "fill the gap".
In JOSE it survives with a `Recommended-` marker.

**COSE AES-CBC and AES-CTR sit in the private-use range and are registered
Deprecated at the same time.** Values `-65529`…`-65534` are simultaneously
"officially discouraged" and "below the standards range" — a combination that
exists nowhere else in these registries. RFC 9459 §4.2 says why: the placement is
deliberate, to stop anyone using an unauthenticated mode without companion
integrity protection. So "Deprecated" here does **not** mean "was once fine"; it
was registered that way from birth. AES-CTR additionally has no NIST OID at all,
so that axis cannot express it.

**Raw primitives are mostly unregistered.** ChaCha20 without Poly1305 has no
identifier in any registry; AES-ECB, OFB and CFB have OIDs only. The pattern
holds across axes: registries cover what protocols compose, not what libraries
expose.

### Key representation footguns

**COSE integers collide across three different fields.** `1` is OKP as a `kty`,
A128GCM as an `alg`, and P-256 as a `crv`. So are `2`, `3` and `5`. The only
thing disambiguating them is the map label they sit under (`1` vs `3` vs `-1`).
The sign does not save you: `alg` has negative values, but its **positive** range
overlaps `kty` exactly. Any code that flattens a COSE_Key into a generic
integer-keyed structure crosses these silently.

**An Ed25519 private key is 32 bytes in some formats and 64 in others.** JWK `d`,
COSE `d` (`-4`) and RFC 8410 PKCS#8 carry the 32-byte seed; OpenSSH's private
format and libsodium carry 64 (seed ‖ public key). Neither leaks more than the
other, but each fails the other's length check. RFC 8410 adds its own trap: the
seed sits in an OCTET STRING **inside** an OCTET STRING, and the double wrapping
is a recurring parse bug.

**base64 and base64url both decode under a lenient decoder.** JWK uses base64url
unpadded, PEM uses padded standard base64, SSH fingerprints unpadded standard,
PGP hex, did:key base58btc, COSE raw bytes. Padding mismatches usually throw;
**alphabet mismatches usually do not** — `+`/`/` versus `-`/`_` silently yield
corrupted key material.

**Point compression is a computation, not a transcoding.** COSE EC2 `y` (`-3`)
may be a boolean sign bit; JWK requires the full coordinate and has no compressed
form; did:key *mandates* compressed for the NIST curves. Converting
COSE-compressed or did:key into JWK requires a modular square root over the curve
field. Libraries treating it as re-encoding produce wrong keys.

**RSA CRT parameters are all-or-nothing in JWK and individually optional in
COSE.** RFC 7518 §6.3.2 requires that if any of `p,q,dp,dq,qi` appears, all must;
COSE labels `-4`…`-8` are independently optional. A COSE key with `p` and no `q`
is legal COSE and illegal JWK. And the names differ in both case and spelling —
COSE `dP`/`dQ`/`qInv`/`other` against JWK `dp`/`dq`/`qi`/`oth` — so a name-based
mapper silently drops three of the four.

**`AKP` without `alg` is unusable.** The key type conveys no parameter set, no
key size, no algorithm. Omit `alg` and you cannot tell ML-DSA-44 from -87,
cannot validate the length of `pub`, and cannot compute a thumbprint (`alg` is a
required member). Validators built on "the key type determines the key shape"
break here.

**Ed25519 has two PGP algorithm IDs with different wire forms.** `22`
(EdDSALegacy, MPI encoding) and `27` (Ed25519, fixed-length octets). MPIs strip
leading zeros, so the same key serialises to different lengths — and therefore
**produces different fingerprints** depending on which ID was used.

**SSH carries the curve name twice.** An ECDSA blob is
`string "ecdsa-sha2-nistp256" ‖ string "nistp256" ‖ string <point>`, and both
must agree; parsers reading only the outer name accept mismatched blobs.
Separately, `ssh-rsa`, `rsa-sha2-256` and `rsa-sha2-512` are three *signature*
algorithms over **one** key format — the blob always says `ssh-rsa`, so treating
the signature name as a key type mislabels keys.

**Round-trips lose fields in both directions.** JWK `use` has no COSE
counterpart; COSE `Base IV` (label `5`) has no JWK counterpart. RFC 7517 also
says `use` and `key_ops` should not both be set and must be consistent if they
are — without defining a machine-checkable consistency rule.

**Every multicodec key code is draft status**, including the post-quantum ones.
Because `did:key` identifiers are derived from the code, a codepoint revision
changes the identifier: persisted DIDs become unresolvable, or resolve to a
different key type.

## Registries cited

| Registry | URL |
|---|---|
| COSE Algorithms | https://www.iana.org/assignments/cose/cose.xhtml#algorithms |
| COSE Elliptic Curves | https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves |
| JOSE Web Signature and Encryption Algorithms | https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms |
| TLS SignatureScheme | https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme |
| TLS Supported Groups | https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8 |
| AEAD Algorithms (RFC 5116) | https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml |
| HPKE KEM / KDF / AEAD ids (RFC 9180) | https://www.iana.org/assignments/hpke/hpke.xhtml |
| Named Information Hash Algorithm (RFC 6920) | https://www.iana.org/assignments/named-information/named-information.xhtml |
| SMI Security for PKIX (OID arc `1.3.6.1.5.5.7.6`) | https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml |
| NIST CSOR (NIST algorithm OIDs) | https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration |
| multicodec (not IANA) | https://github.com/multiformats/multicodec/blob/master/table.csv |

## Contributing

Corrections are the most valuable contribution — especially a value checked
against its registry and found wrong here. Open an issue or a pull request with
the registry URL you checked; that is the whole review process.

Two rules keep this from turning into something it should not be:

1. **No identifiers are assigned here.** If an algorithm lacks a codepoint in
   the registry that ought to have one, the fix is to register it there. Adding
   a private value would make this a registry, with the permanent obligations
   that follow.
2. **Every value cites the registry it came from.** A number without a
   provenance is a guess.

New axes are welcome (signature schemes for specific protocols, hardware token
identifiers, national standards), on the same terms.

## Data provenance

Every value was read from a primary source — an IANA registry page, an RFC, or
the multicodec table — rather than from another aggregator. Where a value comes
from a draft rather than a published RFC, the `status` column says so, because
draft codepoints can change.

The first draft was assembled by hand, which is a process that can be
confidently and invisibly wrong. So the numbers are no longer asked to be
trusted: [`scripts/`](scripts/README.md) re-derives them from the registries,
and everything it can reach has been re-checked.

```
cd scripts
uv run check_iana.py            # COSE, JOSE, TLS, HPKE, AEAD, SSH, OpenPGP, PKIX OIDs
uv run check_multicodec.py      # multicodec and multihash codes
uv run check_key_params.py      # COSE_Key and JWK field labels
uv run check_oids.py            # OID syntax, arcs, cross-file agreement
uv run check_cipher_suites.py   # suite numbers, names, Recommended, decomposition
uv run check_status.py          # the status column, against registry references
uv run check_references.py      # RFC numbers cited in the notes
uv run check_shape.py           # CSV structure; no network, always runs
uv run check_iana.py --new      # list entries the map does not cite
```

All eight are clean at the last run: 318 IANA citations, 43 multicodec codes, 57
field labels, 164 OIDs, 22 cipher suites, 188 status cells, 27 RFC citations and
296 well-formed rows.

**What that does and does not cover.** Of 1573 non-empty cells, 65% are compared
against an external source, 20% are structural or cross-checked between files,
and 14% — the `notes` column, and only that — cannot be machine-verified at all.
There is no registry of assertions about algorithms, so a note's RFC numbers are
checked while the claim wrapped around them is not.

The map's one published factual error lived in exactly that gap: a note
asserting that `0x0840`/`0x0841` held GOST under RFC 9189 and were later
reallocated, which is wrong in both halves (see the footgun above). Every check
passed; a reader's question caught it. **The identifiers here are verified. The
prose is reviewed, which is not the same thing.**

OIDs sit in between. NIST CSOR publishes its arc as HTML, and the ANSI and
RSADSI arcs are not published as data at all; only the PKIX arc, where the
composite signature OIDs live, has a registry. So OIDs get a syntax check, a
known-arc test and a cross-file consistency check — enough to catch a mistyped
digit, not enough to confirm that a well-formed OID is the right one.

## License

[CC-BY-4.0](LICENSE). Copy it, fork it, embed it in your own documentation —
just keep the attribution, so anyone downstream can trace where the numbers came
from and when they were checked.
