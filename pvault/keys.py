"""Armored key files: base64 with PEM-style headers."""

import base64

EK_HEADER = "PQC-VAULT ENCAPSULATION KEY"
DK_HEADER = "PQC-VAULT DECAPSULATION KEY"


def _armor(header: str, raw: bytes) -> str:
    b64 = base64.b64encode(raw).decode("ascii")
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {header}-----\n{lines}\n-----END {header}-----\n"


def _dearmor(header: str, text: str) -> bytes:
    begin = f"-----BEGIN {header}-----"
    end = f"-----END {header}-----"
    try:
        body = text.split(begin, 1)[1].split(end, 1)[0]
    except IndexError:
        raise ValueError(f"not a {header} file")
    return base64.b64decode("".join(body.split()))


def armor_ek(raw: bytes) -> str:
    return _armor(EK_HEADER, raw)


def armor_dk(raw: bytes) -> str:
    return _armor(DK_HEADER, raw)


def dearmor_ek(text: str) -> bytes:
    key = _dearmor(EK_HEADER, text)
    if len(key) != 1184:
        raise ValueError("bad encapsulation key length")
    return key


def dearmor_dk(text: str) -> bytes:
    key = _dearmor(DK_HEADER, text)
    if len(key) != 2400:
        raise ValueError("bad decapsulation key length")
    return key
