"""PQC Vault CLI.

    python -m pvault keygen --out mykey
        writes mykey.ek (shareable) and mykey.dk (keep secret)

    python -m pvault encrypt --key mykey.ek --in genome.vcf --out genome.vcf.pqcv

    python -m pvault decrypt --key mykey.dk --in genome.vcf.pqcv --out genome.vcf

    python -m pvault bench
        timings for keygen, encaps/decaps, and bulk AES throughput
"""

import argparse
import os
import sys
import time

from .crypto import generate_keypair, encrypt, decrypt
from .keys import armor_ek, armor_dk, dearmor_ek, dearmor_dk


def cmd_keygen(args):
    ek, dk = generate_keypair()
    with open(args.out + ".ek", "w") as f:
        f.write(armor_ek(ek))
    with open(args.out + ".dk", "w") as f:
        f.write(armor_dk(dk))
    os.chmod(args.out + ".dk", 0o600)
    print(f"wrote {args.out}.ek (public, shareable)")
    print(f"wrote {args.out}.dk (SECRET - chmod 600 applied)")


def cmd_encrypt(args):
    with open(args.key) as f:
        ek = dearmor_ek(f.read())
    with open(args.in_, "rb") as f:
        plaintext = f.read()
    blob = encrypt(ek, plaintext)
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"encrypted {len(plaintext)} bytes -> {args.out} "
          f"({len(blob)} bytes)")


def cmd_decrypt(args):
    with open(args.key) as f:
        dk = dearmor_dk(f.read())
    with open(args.in_, "rb") as f:
        blob = f.read()
    try:
        plaintext = decrypt(dk, blob)
    except Exception as e:
        print(f"decryption failed: {e}", file=sys.stderr)
        sys.exit(1)
    with open(args.out, "wb") as f:
        f.write(plaintext)
    print(f"decrypted {len(blob)} bytes -> {args.out} "
          f"({len(plaintext)} bytes)")


def cmd_bench(_args):
    from kyber_py.ml_kem import ML_KEM_768
    t0 = time.time()
    ek, dk = ML_KEM_768.keygen()
    t_keygen = time.time() - t0

    t0 = time.time()
    for _ in range(20):
        K, ct = ML_KEM_768.encaps(ek)
    t_encaps = (time.time() - t0) / 20

    t0 = time.time()
    for _ in range(20):
        ML_KEM_768.decaps(dk, ct)
    t_decaps = (time.time() - t0) / 20

    payload = os.urandom(50 << 20)  # 50 MiB synthetic "genomic" payload
    t0 = time.time()
    blob = encrypt(ek, payload)
    t_enc = time.time() - t0
    t0 = time.time()
    out = decrypt(dk, blob)
    t_dec = time.time() - t0
    assert out == payload

    mb = len(payload) / (1 << 20)
    print(f"ML-KEM-768 keygen : {t_keygen * 1000:7.1f} ms")
    print(f"ML-KEM-768 encaps: {t_encaps * 1000:7.1f} ms")
    print(f"ML-KEM-768 decaps: {t_decaps * 1000:7.1f} ms")
    print(f"AES-256-GCM encrypt {mb:.0f} MiB: {t_enc:.2f} s "
          f"({mb / t_enc:6.1f} MiB/s)")
    print(f"AES-256-GCM decrypt {mb:.0f} MiB: {t_dec:.2f} s "
          f"({mb / t_dec:6.1f} MiB/s)")


def main():
    p = argparse.ArgumentParser(prog="pvault",
                                description="Post-quantum vault for genomic data")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an ML-KEM-768 keypair")
    g.add_argument("--out", required=True, help="key basename")
    g.set_defaults(fn=cmd_keygen)

    e = sub.add_parser("encrypt", help="encrypt a file")
    e.add_argument("--key", required=True, help=".ek encapsulation key file")
    e.add_argument("--in", dest="in_", required=True, help="input file")
    e.add_argument("--out", required=True, help="output .pqcv file")
    e.set_defaults(fn=cmd_encrypt)

    d = sub.add_parser("decrypt", help="decrypt a .pqcv file")
    d.add_argument("--key", required=True, help=".dk decapsulation key file")
    d.add_argument("--in", dest="in_", required=True, help="input .pqcv file")
    d.add_argument("--out", required=True, help="output file")
    d.set_defaults(fn=cmd_decrypt)

    b = sub.add_parser("bench", help="benchmark the primitives")
    b.set_defaults(fn=cmd_bench)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
