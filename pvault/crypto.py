"""PQC Vault: hybrid post-quantum encryption for genomic data.

Construction (per file):
  1. ML-KEM-768 encapsulation against the recipient's public key -> (K, ct)
     K is a 32-byte shared secret that is quantum-safe.
  2. KDF: aes_key = SHAKE256(b"PQCV1-HYBRID" || K || nonce_prefix)[0:32]
  3. Plaintext split into 1 MiB chunks; each chunk encrypted with
     AES-256-GCM under (nonce = nonce_prefix || chunk_index_BE32),
     AAD = MAGIC || VERSION || chunk_index_BE32 (binds chunk order).

File layout (all integers big-endian):
  MAGIC      4 bytes  b"PQCV"
  VERSION    1 byte   0x01
  KEM_ID     1 byte   0x01 = ML-KEM-768
  CT_LEN     2 bytes  length of KEM ciphertext (1088)
  CT         CT_LEN bytes
  NONCE_PFX  8 bytes  random per file
  NCHUNKS    4 bytes
  per chunk: CHUNK_LEN 4 bytes || ciphertext+tag

Why hybrid: ML-KEM moves only a 32-byte secret; bulk data goes through
AES-256-GCM, which is quantum-resistant (Grover halves its strength, hence
256-bit keys). This is the standard NIST-recommended migration pattern.
"""

import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_768

MAGIC = b"PQCV"
VERSION = 0x01
KEM_MLKEM768 = 0x01
CHUNK_SIZE = 1 << 20  # 1 MiB

_KEM = ML_KEM_768
_CT_LEN = 1088  # ML-KEM-768 ciphertext bytes


def generate_keypair():
    """Return (encapsulation_key, decapsulation_key) as raw bytes."""
    return _KEM.keygen()  # (ek, dk)


def _kdf(shared_secret: bytes, nonce_prefix: bytes) -> bytes:
    shake = hashlib.shake_256()
    shake.update(b"PQCV1-HYBRID" + shared_secret + nonce_prefix)
    return shake.digest(32)


def _aad(chunk_index: int) -> bytes:
    return MAGIC + bytes([VERSION]) + struct.pack(">I", chunk_index)


def encrypt(encapsulation_key: bytes, plaintext: bytes) -> bytes:
    K, ct = _KEM.encaps(encapsulation_key)
    assert len(ct) == _CT_LEN
    nonce_prefix = os.urandom(8)
    aes_key = _kdf(K, nonce_prefix)
    aesgcm = AESGCM(aes_key)

    chunks = [plaintext[i:i + CHUNK_SIZE]
              for i in range(0, len(plaintext), CHUNK_SIZE)] or [b""]
    out = bytearray()
    out += MAGIC + bytes([VERSION, KEM_MLKEM768])
    out += struct.pack(">H", len(ct)) + ct
    out += nonce_prefix
    out += struct.pack(">I", len(chunks))
    for i, chunk in enumerate(chunks):
        nonce = nonce_prefix + struct.pack(">I", i)
        enc = aesgcm.encrypt(nonce, chunk, _aad(i))
        out += struct.pack(">I", len(enc)) + enc
    return bytes(out)


def decrypt(decapsulation_key: bytes, blob: bytes) -> bytes:
    off = 0
    if blob[off:off + 4] != MAGIC:
        raise ValueError("not a PQCV file (bad magic)")
    off += 4
    if blob[off] != VERSION:
        raise ValueError(f"unsupported version {blob[off]}")
    off += 1
    if blob[off] != KEM_MLKEM768:
        raise ValueError("unsupported KEM id")
    off += 1
    (ct_len,) = struct.unpack_from(">H", blob, off)
    off += 2
    ct = blob[off:off + ct_len]
    off += ct_len
    nonce_prefix = blob[off:off + 8]
    off += 8
    (n_chunks,) = struct.unpack_from(">I", blob, off)
    off += 4

    K = _KEM.decaps(decapsulation_key, ct)
    aes_key = _kdf(K, nonce_prefix)
    aesgcm = AESGCM(aes_key)

    chunks = []
    for i in range(n_chunks):
        (clen,) = struct.unpack_from(">I", blob, off)
        off += 4
        enc = blob[off:off + clen]
        off += clen
        nonce = nonce_prefix + struct.pack(">I", i)
        chunks.append(aesgcm.decrypt(nonce, enc, _aad(i)))
    return b"".join(chunks)
