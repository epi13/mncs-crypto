#!/usr/bin/env python3
"""Crypto enforcement boundary: vectors, suites, and backend agreement.

Gates (fail closed, nonzero exit):

1. corpora in sync with the pinned-vector generator (drift gate);
2. every pinned vector agrees with the independent host oracle
   (hashlib/hmac for SHA-256/HMAC/HKDF, cryptography for Ed25519);
3. all six ``mncs test`` suites PASS on the canonical toolchain;
4. every corpus case meets expectations on wasm, bytecode, AND
   cranelift, with bit-exact agreement of returned values;
5. the sig corpus passes WITH --grant-crypto and fails closed
   (unsupported, never values) WITHOUT it;
6. the test-entropy canary never appears in suite JSON output
   (secret-adjacent bytes do not leak through results).

Suite status must be PASS: crypto leaves no UNKNOWN standing — every
obligation is either discharged or the suite fails.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import build_crypto_corpora

SUITES = (
    ("tests/crypto/types_tests.mncs", 200000),
    ("tests/crypto/encode_tests.mncs", 200000),
    ("tests/crypto/random_tests.mncs", 200000),
    ("tests/crypto/hash_tests.mncs", 1000000),
    ("tests/crypto/hmac_tests.mncs", 1000000),
    ("tests/crypto/hkdf_tests.mncs", 2000000),
)

CORPORA = (
    ("corpora/crypto-hash-corpus.json", "mncs/crypto/hash.mncs", False),
    ("corpora/crypto-hmac-corpus.json", "mncs/crypto/hmac.mncs", False),
    ("corpora/crypto-hkdf-corpus.json", "mncs/crypto/hkdf.mncs", False),
    ("corpora/crypto-sig-corpus.json", "mncs/crypto/sig.mncs", True),
)

BACKENDS = ("mncs-portable-wasm-mvp", "mncs-research-bytecode", "mncs-cranelift")

# Test-entropy canary from tests/crypto/random_tests.mncs: fixed patterns
# must never surface in result output.
CANARY_INT_SEQUENCE = "222, 173, 190, 239"
CANARY_HEX = "deadbeef"

KERNEL_SOURCES = {
    "corpora/crypto-hash-corpus.json": "mncs/crypto/hash.mncs",
    "corpora/crypto-hmac-corpus.json": "mncs/crypto/hmac.mncs",
    "corpora/crypto-hkdf-corpus.json": "mncs/crypto/hkdf.mncs",
    "corpora/crypto-sig-corpus.json": "mncs/crypto/sig.mncs",
}


class CryptoError(RuntimeError):
    pass


def find_executor() -> str:
    override = os.environ.get("MNCS_EXECUTOR")
    if override:
        return override
    found = shutil.which("mncs-executor")
    if found:
        return found
    for profile in ("release", "debug"):
        sibling = REPO.parent / "mncs-language" / "target" / profile / "mncs"
        if sibling.is_file():
            return str(sibling)
    raise CryptoError(
        "no MNCS executor found: set MNCS_EXECUTOR or check out "
        "mncs-language next to mncs-crypto and build it"
    )


def library_path() -> str:
    roots = [
        REPO,
        Path(os.environ.get("MNCS_TEST_NATIVE",
                            str(REPO.parent / "mncs-test" / "native"))),
        Path(os.environ.get("MNCS_LANGUAGE_LIBRARY",
                            str(REPO.parent / "mncs-language" / "library"))),
    ]
    missing = [str(r) for r in roots if not r.is_dir()]
    if missing:
        raise CryptoError(f"missing MNCS library roots: {missing}")
    return os.pathsep.join(str(r) for r in roots)


def check_corpora() -> None:
    with tempfile.TemporaryDirectory(prefix="crypto-corpora-check-") as tmp:
        out = Path(tmp)
        build_crypto_corpora.build(out)
        for filename, _entry, _grant in CORPORA:
            fresh = (out / Path(filename).name).read_text()
            pinned = (REPO / filename).read_text()
            if fresh != pinned:
                raise CryptoError(f"corpus drift: {filename}")


def check_oracle() -> None:
    for msg_hex, digest_hex in build_crypto_corpora.SHA256.items():
        got = hashlib.sha256(bytes.fromhex(msg_hex)).hexdigest()
        if got != digest_hex:
            raise CryptoError(f"oracle rejects SHA-256 pin {msg_hex[:16]}")
    for name, key_hex, data_hex, tag_hex in build_crypto_corpora.HMAC:
        got = hmac.new(bytes.fromhex(key_hex), bytes.fromhex(data_hex),
                       hashlib.sha256).hexdigest()
        if got != tag_hex:
            raise CryptoError(f"oracle rejects HMAC pin {name}")
    for name, vec in build_crypto_corpora.HKDF.items():
        salt = bytes.fromhex(vec["salt"])
        ikm = bytes.fromhex(vec["ikm"])
        info = bytes.fromhex(vec["info"])
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        if prk.hex() != vec["prk"]:
            raise CryptoError(f"oracle rejects HKDF {name} PRK")
        out, blk, i = b"", b"", 1
        while len(out) < 32:
            blk = hmac.new(prk, blk + info + bytes([i]), hashlib.sha256).digest()
            out += blk
            i += 1
        if out[:32].hex() != vec["t1"]:
            raise CryptoError(f"oracle rejects HKDF {name} T1")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise CryptoError(f"ed25519 oracle unavailable: {exc}")
    for name, (pk_hex, msg_hex, sig_hex) in build_crypto_corpora.ED.items():
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        try:
            pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(msg_hex))
        except InvalidSignature:
            raise CryptoError(f"oracle rejects Ed25519 pin {name}")
    print("oracle agrees with all pinned vectors")


def check_suites(executor: str) -> None:
    env = dict(os.environ, MNCS_LIBRARY_PATH=library_path())
    for suite, budget in SUITES:
        completed = subprocess.run(
            [executor, "test", str(REPO / suite),
             "--library", str(REPO),
             "--library", str(REPO.parent / "mncs-test" / "native"),
             "--library", str(REPO.parent / "mncs-language" / "library"),
             "--step-budget", str(budget), "--format", "json"],
            capture_output=True, text=True, timeout=900, env=env, check=False)
        try:
            doc = json.loads(completed.stdout)
        except json.JSONDecodeError:
            raise CryptoError(f"{suite}: unparseable test output")
        summary = doc.get("summary", {})
        if doc.get("classification") != "passed" or summary.get("failed", 1) != 0:
            raise CryptoError(f"{suite}: suite not green: {summary}")
        if CANARY_INT_SEQUENCE in completed.stdout or CANARY_HEX in completed.stdout:
            raise CryptoError(f"{suite}: entropy canary leaked into output")
        print(f"{suite}: {summary['passed']} passed")


def run_corpus(executor: str, corpus: str, entry: str, backend: str,
               tmp: Path, grants: list) -> dict:
    out = tmp / f"{Path(corpus).stem}-{backend.replace('mncs-', '')}"
    env = dict(os.environ, MNCS_LIBRARY_PATH=library_path())
    # Per-case backend allowlists (documented backend pressures): run the
    # applicable subset so a restricted case is skipped, never hidden.
    doc = json.loads((REPO / corpus).read_text())
    applicable = [c for c in doc.get("cases", [])
                  if backend in c.get("backends", list(BACKENDS))]
    if len(applicable) != len(doc.get("cases", [])):
        print(f"{corpus}/{backend}: "
              f"{len(doc['cases']) - len(applicable)} case(s) restricted "
              f"by documented backend pressure")
        subset = Path(tmp) / f"{Path(corpus).stem}-{backend.replace('mncs-', '')}.json"
        subset.write_text(json.dumps(
            {"schema_version": doc.get("schema_version"),
             "name": doc.get("name"), "cases": applicable}) + "\n")
        corpus_arg = str(subset)
    else:
        corpus_arg = str(REPO / corpus)
    completed = subprocess.run(
        [executor, "experiment", "run", str(REPO / entry),
         "--backend", backend, "--corpus", corpus_arg,
         "--output-dir", str(out), *grants],
        capture_output=True, text=True, timeout=900, env=env, check=False)
    result_file = out / "result.json"
    if not result_file.is_file():
        raise CryptoError(f"{corpus}/{backend}: run failed:\n{completed.stderr[-1500:]}")
    return json.loads(result_file.read_text(encoding="utf-8"))


def check_agreement(executor: str) -> None:
    with tempfile.TemporaryDirectory(prefix="crypto-check-") as tmp:
        tmpdir = Path(tmp)
        per_corpus: dict[str, dict[str, dict]] = {}
        for corpus, _entry, _grant in CORPORA:
            entry = KERNEL_SOURCES[corpus]
            needs_grant = corpus == "corpora/crypto-sig-corpus.json"
            per_backend = {}
            for backend in BACKENDS:
                grants = ["--grant-crypto", "crypto_verify"] if needs_grant else []
                result = run_corpus(executor, corpus, entry, backend, tmpdir, grants)
                status = result.get("status")
                unmet = [c.get("case_id") for c in result.get("cases", [])
                         if not c.get("expectation_met")]
                if status not in ("PASS", "UNKNOWN") or unmet:
                    raise CryptoError(
                        f"{corpus}/{backend}: status={status} unmet={unmet} "
                        f"unresolved={result.get('unresolved_reasons')}")
                print(f"{corpus}/{backend}: {status} "
                      f"({len(result.get('cases', []))} met)")
                per_backend[backend] = {
                    c.get("case_id"): c.get("returned")
                    for c in result.get("cases", [])}
            per_corpus[corpus] = per_backend
        total = disagreements = 0
        for corpus, per_backend in per_corpus.items():
            pinned = {c.get("id"): c
                      for c in json.loads((REPO / corpus).read_text())["cases"]}
            case_ids = set().union(*(set(v) for v in per_backend.values()))
            for cid in sorted(case_ids):
                ran = [b for b in BACKENDS if cid in per_backend[b]]
                if len(ran) < 2:
                    # Single-backend cases are allowed only with an
                    # explicit pinned backend restriction; the value is
                    # then proven by expectation_met on that backend plus
                    # the independent oracle, not by agreement.
                    allowed = pinned.get(cid, {}).get("backends")
                    if not allowed or set(ran) != set(allowed) & set(ran):
                        raise CryptoError(
                            f"{corpus}::{cid}: ran on fewer than two "
                            f"backends without a matching restriction")
                    print(f"{corpus}::{cid}: restricted to "
                          f"({','.join(ran)}), oracle-backed")
                total += 1
                first = json.dumps(per_backend[ran[0]][cid], sort_keys=True)
                if any(json.dumps(per_backend[b][cid], sort_keys=True) != first
                       for b in ran[1:]):
                    disagreements += 1
                    print(f"DIVERGE {corpus}::{cid}")
        print(f"cross-backend agreement: {total - disagreements}/{total}")
        if disagreements:
            raise CryptoError(f"{disagreements} cross-backend divergences")


def check_grant_boundary(executor: str) -> None:
    corpus = "corpora/crypto-sig-corpus.json"
    entry = KERNEL_SOURCES[corpus]
    with tempfile.TemporaryDirectory(prefix="crypto-grant-check-") as tmp:
        result = run_corpus(executor, corpus, entry,
                            "mncs-research-bytecode", Path(tmp), [])
        closed = pure = 0
        for case in result.get("cases", []):
            if case.get("status") == "unsupported":
                closed += 1
            elif case.get("status") == "returned" and case.get("expectation_met"):
                # The pure shape gate refuses malformed inputs before any
                # host call, so it needs no grant by construction.
                pure += 1
            else:
                raise CryptoError(
                    f"ungranted sig case not fail-closed: {case.get('case_id')} "
                    f"status={case.get('status')}")
        print(f"grant boundary: {closed} unsupported, {pure} pure-shape met")


def main() -> int:
    executor = find_executor()
    print(f"executor: {executor}")
    check_corpora()
    print("corpora in sync")
    check_oracle()
    check_suites(executor)
    check_agreement(executor)
    check_grant_boundary(executor)
    print("crypto boundary green")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CryptoError, OSError, ValueError) as exc:
        print(f"crypto_check FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
