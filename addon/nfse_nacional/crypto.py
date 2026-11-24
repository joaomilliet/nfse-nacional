"""Pure standard-library cryptography the NFS-e needs: a BER/DER reader, the ciphers a PKCS#12 (.pfx) file is
locked with (AES, Triple DES, RC2), the PKCS#12 and PBKDF2 key derivations, reading the RSA key and certificates out of
the .pfx, and RSA PKCS#1 v1.5 signatures.

Nothing here is used for anything but reading the company's own certificate and signing its own documents.
"""
from __future__ import annotations

import base64
import hashlib
from typing import List, Optional, Tuple


class CryptoError(ValueError):
    pass


# ---- BER / DER reader -------------------------------------------------------------------------------------------
def read(b: bytes, i: int = 0) -> Tuple[int, bytes, int]:
    """One element at b[i]: (tag, content, end). Indefinite lengths (BER) are followed to their end-of-contents."""
    if i >= len(b):
        raise CryptoError("truncated data")
    tag = b[i]
    i += 1
    if tag & 0x1F == 0x1F:
        while b[i] & 0x80:
            i += 1
        i += 1
    ln = b[i]
    i += 1
    if ln == 0x80:
        start = j = i
        while not (b[j] == 0 and b[j + 1] == 0):
            j = read(b, j)[2]
        return tag, b[start:j], j + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    if i + ln > len(b):
        raise CryptoError("truncated data")
    return tag, b[i:i + ln], i + ln


def children(content: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i < len(content):
        if content[i] == 0 and i + 1 < len(content) and content[i + 1] == 0:
            break
        t, c, i = read(content, i)
        out.append((t, c))
    return out


def octets(tag: int, content: bytes) -> bytes:
    """An OCTET STRING's bytes, joined when it came in constructed pieces."""
    if tag & 0x20:
        return b"".join(octets(t, c) for t, c in children(content))
    return content


def oid(content: bytes) -> str:
    parts = [content[0] // 40, content[0] % 40]
    v = 0
    for x in content[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def integer(content: bytes) -> int:
    return int.from_bytes(content, "big", signed=True)


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(s)]) + s


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


# ---- AES (decryption) -------------------------------------------------------------------------------------------
def _xt(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        sbox[x] = s ^ 0x63
    isbox = [0] * 256
    for i, v in enumerate(sbox):
        isbox[v] = i
    return sbox, isbox


_SBOX, _ISBOX = _make_sbox()
_M9 = [_gmul(x, 9) for x in range(256)]
_M11 = [_gmul(x, 11) for x in range(256)]
_M13 = [_gmul(x, 13) for x in range(256)]
_M14 = [_gmul(x, 14) for x in range(256)]


class AES:
    def __init__(self, key: bytes):
        nk = len(key) // 4
        if len(key) not in (16, 24, 32):
            raise CryptoError("AES key must be 16, 24 or 32 bytes")
        self.nr = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, 4 * (self.nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[x] for x in t]
                t[0] ^= rcon
                rcon = _xt(rcon)
            elif nk > 6 and i % nk == 4:
                t = [_SBOX[x] for x in t]
            w.append([w[i - nk][k] ^ t[k] for k in range(4)])
        self.w = w

    def _add(self, s, rnd):
        for c in range(4):
            wk = self.w[rnd * 4 + c]
            for r in range(4):
                s[4 * c + r] ^= wk[r]

    def decrypt_block(self, block: bytes) -> bytes:
        s = list(block)
        self._add(s, self.nr)
        for rnd in range(self.nr - 1, -1, -1):
            s = [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]
            s = [_ISBOX[x] for x in s]
            self._add(s, rnd)
            if rnd:
                out = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    out += [_M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
                            _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                            _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
                            _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]]
                s = out
        return bytes(s)

    block_size = 16


# ---- DES / Triple DES (decryption) ------------------------------------------------------------------------------
_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
       32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
       55, 47, 39, 31, 23, 15, 7]
_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13,
       53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
       33, 1, 41, 9, 49, 17, 57, 25]
_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20,
      21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11,
      4, 25]
_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
        55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _perm(v: int, table, width: int) -> int:
    out = 0
    for p in table:
        out = (out << 1) | ((v >> (width - p)) & 1)
    return out


class DES:
    block_size = 8

    def __init__(self, key: bytes):
        k = _perm(int.from_bytes(key, "big"), _PC1, 64)
        c, d = k >> 28, k & 0xFFFFFFF
        self.sub = []
        for s in _SHIFTS:
            c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
            d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
            self.sub.append(_perm((c << 28) | d, _PC2, 56))

    def _crypt(self, block: bytes, keys) -> bytes:
        v = _perm(int.from_bytes(block, "big"), _IP, 64)
        l, r = v >> 32, v & 0xFFFFFFFF
        for k in keys:
            x = _perm(r, _E, 32) ^ k
            f = 0
            for i in range(8):
                b6 = (x >> (42 - 6 * i)) & 0x3F
                row = ((b6 & 0x20) >> 4) | (b6 & 1)
                col = (b6 >> 1) & 0xF
                f = (f << 4) | _S[i][row * 16 + col]
            l, r = r, l ^ _perm(f, _P, 32)
        return _perm((r << 32) | l, _FP, 64).to_bytes(8, "big")

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, self.sub)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, self.sub[::-1])


class TripleDES:
    block_size = 8

    def __init__(self, key: bytes):
        if len(key) == 16:
            key = key + key[:8]
        self.k1, self.k2, self.k3 = DES(key[:8]), DES(key[8:16]), DES(key[16:24])

    def decrypt_block(self, block: bytes) -> bytes:
        return self.k1.decrypt_block(self.k2.encrypt_block(self.k3.decrypt_block(block)))


# ---- RC2 (decryption, RFC 2268) ---------------------------------------------------------------------------------
_PI = bytes.fromhex(
    "d978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2"
    "179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82"
    "54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626"
    "6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7"
    "08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec"
    "c2e0416e0f51cbcc2491af50a1f4703999 7c3a8523b8b47afc02365b255597312d"
    "5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a90d"
    "38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad".replace(" ", ""))


class RC2:
    block_size = 8

    def __init__(self, key: bytes, bits: int):
        t = len(key)
        t8 = (bits + 7) // 8
        tm = 255 % (1 << (8 + bits - 8 * t8))
        l = list(key) + [0] * (128 - t)
        for i in range(t, 128):
            l[i] = _PI[(l[i - 1] + l[i - t]) & 255]
        l[128 - t8] = _PI[l[128 - t8] & tm]
        for i in range(127 - t8, -1, -1):
            l[i] = _PI[l[i + 1] ^ l[i + t8]]
        self.k = [l[2 * i] | (l[2 * i + 1] << 8) for i in range(64)]

    def decrypt_block(self, block: bytes) -> bytes:
        k = self.k
        r = [block[0] | block[1] << 8, block[2] | block[3] << 8, block[4] | block[5] << 8, block[6] | block[7] << 8]
        j = [63]
        sh = (1, 2, 3, 5)

        def mix():
            for i in (3, 2, 1, 0):
                x = r[i]
                r[i] = ((x >> sh[i]) | (x << (16 - sh[i]))) & 0xFFFF
                r[i] = (r[i] - k[j[0]] - (r[(i - 1) % 4] & r[(i - 2) % 4]) - ((~r[(i - 1) % 4]) & r[(i - 3) % 4])) & 0xFFFF
                j[0] -= 1

        def mash():
            for i in (3, 2, 1, 0):
                r[i] = (r[i] - k[r[(i - 1) % 4] & 63]) & 0xFFFF

        for _ in range(5):
            mix()
        mash()
        for _ in range(6):
            mix()
        mash()
        for _ in range(5):
            mix()
        return bytes([r[0] & 255, r[0] >> 8, r[1] & 255, r[1] >> 8, r[2] & 255, r[2] >> 8, r[3] & 255, r[3] >> 8])


def cbc_decrypt(cipher, iv: bytes, data: bytes) -> bytes:
    bs = cipher.block_size
    if not data or len(data) % bs:
        raise CryptoError("encrypted data is not a whole number of blocks")
    out, prev = bytearray(), iv
    for i in range(0, len(data), bs):
        blk = data[i:i + bs]
        out += bytes(a ^ b for a, b in zip(cipher.decrypt_block(blk), prev))
        prev = blk
    pad = out[-1]
    if pad < 1 or pad > bs or out[-pad:] != bytes([pad]) * pad:
        raise CryptoError("bad padding")
    return bytes(out[:-pad])


def selftest() -> dict:
    """Known-answer tests for every cipher (FIPS-197, the classic DES vector, RFC 2268)."""
    res = {}
    aes = AES(bytes(range(16)))
    res["aes"] = aes.decrypt_block(bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")) == bytes.fromhex(
        "00112233445566778899aabbccddeeff")
    d = DES(bytes.fromhex("133457799BBCDFF1"))
    res["des"] = d.decrypt_block(bytes.fromhex("85E813540F0AB405")) == bytes.fromhex("0123456789ABCDEF")
    res["rc2_table"] = len(_PI) == 256 and len(set(_PI)) == 256
    try:
        rc = RC2(bytes(8), 63)
        res["rc2"] = rc.decrypt_block(bytes.fromhex("ebb773f993278eff")) == bytes(8)
        rc = RC2(bytes.fromhex("88bca90e90875a7f0f79c384627bafb2"), 128)
        res["rc2_128"] = rc.decrypt_block(bytes.fromhex("2269552ab0f85ca6")) == bytes(8)
    except Exception:
        res["rc2"] = False
    return res


# ---- key derivations ------------------------------------------------------------------------------------------
def _p12_kdf(password: bytes, salt: bytes, ident: int, iterations: int, n: int, hname: str = "sha1") -> bytes:
    h = hashlib.new(hname)
    u, v = h.digest_size, h.block_size
    d = bytes([ident]) * v

    def stretch(x: bytes) -> bytes:
        if not x:
            return b""
        m = v * ((len(x) + v - 1) // v)
        return (x * (m // len(x) + 1))[:m]

    i_ = stretch(salt) + stretch(password)
    out = b""
    while len(out) < n:
        a = hashlib.new(hname, d + i_).digest()
        for _ in range(iterations - 1):
            a = hashlib.new(hname, a).digest()
        out += a
        b = int.from_bytes((a * (v // u + 1))[:v], "big") + 1
        i_ = b"".join(((int.from_bytes(i_[j:j + v], "big") + b) % (1 << (8 * v))).to_bytes(v, "big")
                       for j in range(0, len(i_), v))
    return out[:n]


_PRF = {"1.2.840.113549.2.7": "sha1", "1.2.840.113549.2.8": "sha224", "1.2.840.113549.2.9": "sha256",
        "1.2.840.113549.2.10": "sha384", "1.2.840.113549.2.11": "sha512"}
_AES = {"2.16.840.1.101.3.4.1.2": 16, "2.16.840.1.101.3.4.1.22": 24, "2.16.840.1.101.3.4.1.42": 32}


def decrypt(alg: bytes, data: bytes, password: str) -> bytes:
    """Decrypts data sealed with the AlgorithmIdentifier `alg` (DER content of the SEQUENCE)."""
    parts = children(alg)
    name = oid(parts[0][1])
    params = parts[1][1] if len(parts) > 1 else b""
    if name.startswith("1.2.840.113549.1.12.1."):
        salt_t, iters_t = children(params)[:2]
        salt, iters = salt_t[1], integer(iters_t[1])
        pw = (password.encode("utf-16-be") + b"\x00\x00")
        kind = name.rsplit(".", 1)[1]
        if kind in ("3", "4"):
            klen = 24 if kind == "3" else 16
            key = _p12_kdf(pw, salt, 1, iters, klen)
            iv = _p12_kdf(pw, salt, 2, iters, 8)
            return cbc_decrypt(TripleDES(key), iv, data)
        if kind in ("5", "6"):
            bits = 128 if kind == "5" else 40
            key = _p12_kdf(pw, salt, 1, iters, bits // 8)
            iv = _p12_kdf(pw, salt, 2, iters, 8)
            return cbc_decrypt(RC2(key, bits), iv, data)
        raise CryptoError("the certificate file uses PKCS#12 algorithm %s, which is not supported" % name)
    if name == "1.2.840.113549.1.5.13":
        kdf, enc = children(params)[:2]
        kdf_parts = children(kdf[1])
        if oid(kdf_parts[0][1]) != "1.2.840.113549.1.5.12":
            raise CryptoError("the certificate file uses a key derivation other than PBKDF2")
        kp = children(kdf_parts[1][1])
        salt, iters = kp[0][1], integer(kp[1][1])
        prf = "sha1"
        klen = None
        for t, c in kp[2:]:
            if t == 0x02:
                klen = integer(c)
            elif t == 0x30:
                prf = _PRF.get(oid(children(c)[0][1]), "")
                if not prf:
                    raise CryptoError("the certificate file uses an unknown PRF")
        enc_parts = children(enc[1])
        ename = oid(enc_parts[0][1])
        iv = enc_parts[1][1]
        pw = password.encode("utf-8")
        if ename in _AES:
            key = hashlib.pbkdf2_hmac(prf, pw, salt, iters, klen or _AES[ename])
            return cbc_decrypt(AES(key), iv, data)
        if ename == "1.2.840.113549.3.7":
            key = hashlib.pbkdf2_hmac(prf, pw, salt, iters, klen or 24)
            return cbc_decrypt(TripleDES(key), iv, data)
        raise CryptoError("the certificate file uses cipher %s, which is not supported" % ename)
    raise CryptoError("the certificate file uses algorithm %s, which is not supported" % name)


# ---- PKCS#12 ----------------------------------------------------------------------------------------------------
class Certificate:
    def __init__(self, der_bytes: bytes):
        self.der = der_bytes
        tbs = children(children(read(der_bytes)[1])[0][1])
        idx = 1 if tbs[0][0] == 0xA0 else 0
        self.serial = integer(tbs[idx][1])
        self.issuer = _name(tbs[idx + 2][1])
        validity = children(tbs[idx + 3][1])
        self.not_before = _time(validity[0])
        self.not_after = _time(validity[1])
        self.subject = _name(tbs[idx + 4][1])
        spki = children(tbs[idx + 5][1])
        bits = spki[1][1][1:]
        nums = children(read(bits)[1])
        self.n, self.e = integer(nums[0][1]), integer(nums[1][1])
        self.cnpj = ""
        self.cpf = ""
        self.aia = ""
        for t, c in tbs[idx + 6:]:
            if t == 0xA3:
                for ext_t, ext in children(children(c)[0][1]):
                    parts = children(ext)
                    eid = oid(parts[0][1])
                    if eid == "2.5.29.17":
                        self._san(octets(*parts[-1]))
                    elif eid == "1.3.6.1.5.5.7.1.1":
                        try:
                            for _, ad in children(read(octets(*parts[-1]))[1]):
                                adp = children(ad)
                                if oid(adp[0][1]) == "1.3.6.1.5.5.7.48.2" and adp[1][0] == 0x86:
                                    self.aia = adp[1][1].decode("ascii", "replace")
                        except Exception:  # noqa: BLE001
                            pass
        cn = self.subject.get("CN", "")
        if not self.cnpj and ":" in cn:
            tail = "".join(ch for ch in cn.rsplit(":", 1)[1] if ch.isdigit())
            if len(tail) == 14:
                self.cnpj = tail

    def _san(self, data: bytes) -> None:
        for t, c in children(read(data)[1]):
            if t != 0xA0:
                continue
            parts = children(c)
            if not parts:
                continue
            name = oid(parts[0][1])
            try:
                inner = read(parts[1][1])
                val = inner[1].decode("latin-1")
            except Exception:
                continue
            digits = "".join(ch for ch in val if ch.isdigit())
            if name == "2.16.76.1.3.3" and len(digits) >= 14:
                self.cnpj = digits[:14]
            elif name == "2.16.76.1.3.1" and len(digits) >= 19:
                self.cpf = digits[8:19]

    def pem(self) -> str:
        b = base64.b64encode(self.der).decode()
        return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % "\n".join(
            b[i:i + 64] for i in range(0, len(b), 64))


_ATTR = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU"}


def _name(content: bytes) -> dict:
    out = {}
    for _, rdn in children(content):
        for _, atv in children(rdn):
            parts = children(atv)
            key = _ATTR.get(oid(parts[0][1]), oid(parts[0][1]))
            t, v = parts[1]
            try:
                s = v.decode("utf-16-be") if t == 0x1E else v.decode("utf-8")
            except UnicodeDecodeError:
                s = v.decode("latin-1")
            out[key] = s if key not in out else out[key] + "; " + s
    return out


def _time(el) -> str:
    t, c = el
    s = c.decode()
    if t == 0x17:
        y = int(s[:2])
        s = ("19" if y >= 50 else "20") + s
    return "%s-%s-%sT%s:%s:%sZ" % (s[0:4], s[4:6], s[6:8], s[8:10], s[10:12], s[12:14])


class RSAKey:
    def __init__(self, pkcs8: bytes):
        self.pkcs8 = pkcs8
        info = children(read(pkcs8)[1])
        if oid(children(info[1][1])[0][1]) != "1.2.840.113549.1.1.1":
            raise CryptoError("the certificate's key is not an RSA key")
        nums = [integer(c) for t, c in children(read(octets(*info[2]))[1])]
        _, self.n, self.e, self.d, self.p, self.q, self.dp, self.dq, self.qi = nums[:9]

    def sign(self, message: bytes, hname: str = "sha256") -> bytes:
        prefix = {"sha256": "3031300d060960864801650304020105000420",
                  "sha1": "3021300906052b0e03021a05000414"}[hname]
        t = bytes.fromhex(prefix) + hashlib.new(hname, message).digest()
        k = (self.n.bit_length() + 7) // 8
        if k < len(t) + 11:
            raise CryptoError("RSA key too short")
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        m = int.from_bytes(em, "big")
        m1 = pow(m, self.dp, self.p)
        m2 = pow(m, self.dq, self.q)
        h = (self.qi * (m1 - m2)) % self.p
        s = m2 + h * self.q
        if pow(s, self.e, self.n) != m:
            raise CryptoError("RSA signature check failed")
        return s.to_bytes(k, "big")

    def pem(self) -> str:
        b = base64.b64encode(self.pkcs8).decode()
        return "-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n" % "\n".join(
            b[i:i + 64] for i in range(0, len(b), 64))


def load_pfx(data: bytes, password: str) -> Tuple[RSAKey, Certificate, List[Certificate]]:
    """The private key, its certificate and the rest of the chain out of a .pfx / .p12 file."""
    try:
        pfx = children(read(data)[1])
        auth = children(pfx[1][1])
        if oid(auth[0][1]) != "1.2.840.113549.1.7.1":
            raise CryptoError("the file is not a PKCS#12 certificate (signed authSafe not supported)")
        safe = octets(*children(auth[1][1])[0])
    except (IndexError, CryptoError) as e:
        raise CryptoError("the file is not a readable .pfx/.p12 certificate (%s)" % e)
    keys: List[RSAKey] = []
    certs: List[Certificate] = []
    for _, ci in children(read(safe)[1]):
        parts = children(ci)
        kind = oid(parts[0][1])
        if kind == "1.2.840.113549.1.7.1":
            contents = octets(*children(parts[1][1])[0])
        elif kind == "1.2.840.113549.1.7.6":
            ed = children(children(parts[1][1])[0][1])
            eci = children(ed[1][1])
            enc = octets(eci[2][0] | 0x00, eci[2][1]) if eci[2][0] & 0x20 else eci[2][1]
            contents = decrypt(eci[1][1], enc, password)
        else:
            continue
        for _, bag in children(read(contents)[1]):
            bp = children(bag)
            bag_id = oid(bp[0][1])
            value = children(bp[1][1])[0]
            if bag_id == "1.2.840.113549.1.12.10.1.1":
                keys.append(RSAKey(der(0x30, value[1])))
            elif bag_id == "1.2.840.113549.1.12.10.1.2":
                epki = children(value[1])
                plain = decrypt(epki[0][1], octets(*epki[1]), password)
                keys.append(RSAKey(plain))
            elif bag_id == "1.2.840.113549.1.12.10.1.3":
                cb = children(value[1])
                if oid(cb[0][1]) == "1.2.840.113549.1.9.22.1":
                    certs.append(Certificate(octets(*children(cb[1][1])[0])))
    if not keys:
        raise CryptoError("no private key was found in the certificate file")
    key = keys[0]
    leaf = next((c for c in certs if c.n == key.n), None)
    if leaf is None:
        raise CryptoError("the certificate file holds no certificate for its private key")
    chain = [c for c in certs if c is not leaf]
    return key, leaf, chain
