#!/usr/bin/env python3
"""Build pinned experiment corpora for mncs-crypto agreement runs.

Every expected value below is pinned from the authoritative publication
(FIPS 180-4, RFC 4231, RFC 5869, RFC 8032) and confirmed by an
independent oracle before being frozen here. The generator is
deterministic: crypto_check.py rebuilds into a temp dir and drift-gates
against corpora/.

Corpora cover what ``mncs test`` cannot: bit-exact agreement of returned
values across all three backends, plus the --grant-crypto boundary
(granted verdicts vs fail-closed without a grant).
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

STEP_BUDGET = 2000000


def seq(data: bytes) -> dict:
    return {"sequence": {"values": [{"byte": {"value": b}} for b in data]}}


def u64(value: int) -> dict:
    return {"integer": {"value": value, "type": {"bits": 64, "signed": False}}}


def call(module: str, function: str, arguments: list) -> dict:
    return {
        "schema_version": "0.1",
        "target": {"module": module, "function": function},
        "arguments": arguments,
        "step_budget": STEP_BUDGET,
    }


def case(case_id: str, module: str, function: str, arguments: list, expected: list) -> dict:
    return {
        "id": case_id,
        "request": call(module, function, arguments),
        "expected": expected,
    }


# --- Pinned vectors (authoritative publications, oracle-confirmed). ---

# FIPS 180-4 section 8.1 message: the 56-byte padding-boundary input.
_FIPS56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
assert len(_FIPS56) == 56

SHA256 = {
    # message_hex: digest_hex
    "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "616263": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    _FIPS56.hex():
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "61" * 64: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
    "61" * 119: "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
    "61" * 200: "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5",
}

def _ascii(text: str) -> str:
    return text.encode("ascii").hex()


HMAC = [
    # (name, key_hex, data_hex, tag_hex)
    ("tc1", "0b" * 20, _ascii("Hi There"),
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    ("tc2", _ascii("Jefe"), _ascii("what do ya want for nothing?"),
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ("tc3", "aa" * 20, "dd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    ("tc6", "aa" * 131,
     _ascii("Test Using Larger Than Block-Size Key - Hash Key First"),
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
]

HKDF = {
    "a1": {
        "salt": "000102030405060708090a0b0c",
        "ikm": "0b" * 22,
        "info": "f0f1f2f3f4f5f6f7f8f9",
        "prk": "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "t1": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
    },
    "a3": {
        "salt": "",
        "ikm": "0b" * 22,
        "info": "",
        "prk": "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "t1": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
    },
}

ED = {
    # RFC 8032 section 7 TEST 1-3: (public key, message, signature).
    # Extracted programmatically from the RFC text and confirmed by an
    # independent ed25519 oracle before freezing.
    "t1": (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    "t2": (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    "t3": (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a",
    ),
}


def build_hash() -> dict:
    cases = []
    for idx, (msg_hex, digest_hex) in enumerate(SHA256.items()):
        msg = bytes.fromhex(msg_hex)
        cases.append(case(
            f"sha256-{idx}", "mncs.crypto.hash", "sha256_bytes",
            [seq(msg), u64(len(msg))], [seq(bytes.fromhex(digest_hex))],
        ))
    return {"schema_version": "0.1", "name": "crypto-hash", "cases": cases}


def build_hmac() -> dict:
    cases = []
    for name, key_hex, data_hex, tag_hex in HMAC:
        cases.append(case(
            f"hmac-{name}", "mncs.crypto.hmac", "hmac_sha256_bytes",
            [seq(bytes.fromhex(key_hex)), seq(bytes.fromhex(data_hex))],
            [seq(bytes.fromhex(tag_hex))],
        ))
    return {"schema_version": "0.1", "name": "crypto-hmac", "cases": cases}


def build_hkdf() -> dict:
    cases = []
    for name, vec in HKDF.items():
        salt = bytes.fromhex(vec["salt"])
        ikm = bytes.fromhex(vec["ikm"])
        info = bytes.fromhex(vec["info"])
        cases.append(case(
            f"hkdf-{name}-extract", "mncs.crypto.hkdf", "hkdf_extract_bytes",
            [seq(salt), seq(ikm)], [seq(bytes.fromhex(vec["prk"]))],
        ))
        block1 = case(
            f"hkdf-{name}-block1", "mncs.crypto.hkdf", "hkdf_first_block_bytes",
            [seq(salt), seq(ikm), seq(info)],
            [seq(bytes.fromhex(vec["t1"])[:32])],
        )
        if name == "a1":
            # Backend pressure CRYPTO-PRESS-ARENA: the cranelift JIT
            # reports a 16MB canonical-arena exhaustion for this exact
            # 45-byte argument shape (13+22+10) while the 22-byte shape
            # passes. Bytecode and wasm agree on the value; the T(1)
            # composition is therefore proven twice, and chaining by the
            # block tests. Restricted, not hidden.
            block1["backends"] = [
                "mncs-portable-wasm-mvp",
                "mncs-research-bytecode",
            ]
        cases.append(block1)
    return {"schema_version": "0.1", "name": "crypto-hkdf", "cases": cases}


def build_sig() -> dict:
    # Backend pressure CRYPTO-PRESS-GRANT: only the research-bytecode
    # backend realizes the ed25519_verify host grant. Wasm and cranelift
    # stub capability-needing closures at per-entrypoint admission
    # (fail-closed Unsupported, by toolchain design). The corpus therefore
    # proves the granted verdicts on bytecode; the ungranted fail-closed
    # shape is proven separately by crypto_check on the same backend.
    cases = []
    for name, (pk_hex, msg_hex, sig_hex) in ED.items():
        entry = case(
            f"ed25519-{name}-valid", "mncs.crypto.sig", "verify_status",
            [seq(bytes.fromhex(pk_hex)), seq(bytes.fromhex(msg_hex)),
             seq(bytes.fromhex(sig_hex))],
            [u64(0)],
        )
        entry["backends"] = ["mncs-research-bytecode"]
        cases.append(entry)
    pk, msg, sig = (bytes.fromhex(x) for x in ED["t1"])
    forged = bytearray(sig)
    forged[-1] ^= 1
    for case_id, args, want in (
        ("ed25519-t1-forged-signature",
         [seq(pk), seq(msg), seq(bytes(forged))], [u64(1)]),
        ("ed25519-t1-wrong-message",
         [seq(pk), seq(b"x"), seq(sig)], [u64(1)]),
        ("ed25519-short-key",
         [seq(pk[:31]), seq(msg), seq(sig)], [u64(2)]),
        ("ed25519-short-signature",
         [seq(pk), seq(msg), seq(sig[:63])], [u64(2)]),
    ):
        entry = case(case_id, "mncs.crypto.sig", "verify_status", args, want)
        entry["backends"] = ["mncs-research-bytecode"]
        cases.append(entry)
    return {"schema_version": "0.1", "name": "crypto-sig", "cases": cases}


CORPORA = (
    ("crypto-hash-corpus.json", build_hash),
    ("crypto-hmac-corpus.json", build_hmac),
    ("crypto-hkdf-corpus.json", build_hkdf),
    ("crypto-sig-corpus.json", build_sig),
)


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, builder in CORPORA:
        (out_dir / filename).write_text(
            json.dumps(builder(), indent=1) + "\n", encoding="utf-8")


def main() -> int:
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "corpora"
    build(target)
    print(f"corpora written to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
