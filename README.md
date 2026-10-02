# PQC Vault

Hybrid post-quantum encryption for genomic data. Protects FASTQ, VCF, BAM —
anything — against **harvest-now-decrypt-later** attacks: adversaries
collecting encrypted genomic data today to decrypt once cryptographically
relevant quantum computers arrive. Your genome never changes, so this is the
data most worth protecting *now*.

## How it works

1. **ML-KEM-768** (FIPS 203, NIST's post-quantum KEM standard) encapsulates a
   32-byte secret to the recipient's public key — quantum-safe key exchange.
2. **SHAKE256-KDF** derives an AES-256 key from that secret.
3. **AES-256-GCM** encrypts the file in 1 MiB chunks, each with a unique nonce
   and AAD binding the chunk index (reordering/tampering is detected).

This hybrid pattern is the NIST-recommended migration path: PQC moves the key,
symmetric crypto moves the bulk data (Grover's algorithm only halves AES
strength, hence 256-bit keys).

## Usage

```bash
pip install -r requirements.txt

# one-time: make a keypair
python -m pvault.cli keygen --out mykey
# -> mykey.ek  (public: share it)
# -> mykey.dk  (SECRET: chmod 600 applied)

# encrypt
python -m pvault.cli encrypt --key mykey.ek --in genome.vcf --out genome.vcf.pqcv

# decrypt
python -m pvault.cli decrypt --key mykey.dk --in genome.vcf.pqcv --out genome.vcf

# benchmark your machine
python -m pvault.cli bench
```

Try it on the samples: `sample/demo.vcf`, `sample/demo.fastq`.

## Benchmarks (reference machine)

| operation              | time   |
|------------------------|--------|
| ML-KEM-768 keygen      | 4.7 ms |
| ML-KEM-768 encaps      | 5.7 ms |
| ML-KEM-768 decaps      | 7.7 ms |
| AES-256-GCM encrypt    | 280 MiB/s |
| AES-256-GCM decrypt    | 465 MiB/s |

PQC operations are one-shot per file; bulk throughput is pure AES speed —
a 1 GB genome encrypts in seconds.

## File format

```
MAGIC      4B  "PQCV"      KEM_ID   1B  0x01 = ML-KEM-768
VERSION    1B  0x01        CT_LEN   2B  BE
CT         1088B           NONCE    8B  random per file
NCHUNKS    4B  BE
per chunk: LEN 4B BE || AES-GCM(nonce_prefix || index_BE32,
                                aad="PQCV"||VER||index_BE32)
```

## Security notes

- Real primitives, real construction — but demo-grade key management: the
  `.dk` file is only chmod-protected, there is no memory wiping, and the
  pure-Python ML-KEM is not constant-time (side-channel hardening is out of
  scope for v1).
- ML-KEM comes from `kyber-py`; AES-GCM from the `cryptography` package.
- Threat model: protects data-at-rest against future quantum decryption.
  It does not anonymize genomes — encrypted is encrypted, but metadata
  (file size, timing) is visible.

## References

- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- NIST PQC standardization project
