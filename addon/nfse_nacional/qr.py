"""QR code (byte mode, error correction M, versions 1-10) as a PNG, standard library only, for the DANFSe's
official consultation link."""
from __future__ import annotations

import base64
import os
import struct
import zlib

from .toolkit import ToolError, data_dir, prop, tool

CONSULTA = "https://www.nfse.gov.br/ConsultaPublica/?tpc=1&chave=%s"

# level M: EC codewords per block, and the blocks as (count, data codewords)
EC = {1: 10, 2: 16, 3: 26, 4: 18, 5: 24, 6: 16, 7: 18, 8: 22, 9: 22, 10: 26}
BLOCKS = {1: [(1, 16)], 2: [(1, 28)], 3: [(1, 44)], 4: [(2, 32)], 5: [(2, 43)], 6: [(4, 27)], 7: [(4, 31)],
          8: [(2, 38), (2, 39)], 9: [(3, 36), (2, 37)], 10: [(4, 43), (1, 44)]}
ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
         9: [6, 26, 46], 10: [6, 28, 50]}

EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def _rs(data: list, deg: int) -> list:
    g = [1]
    for i in range(deg):
        n = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            n[j] ^= c
            n[j + 1] ^= _mul(c, EXP[i])
        g = n
    msg = list(data) + [0] * deg
    for i in range(len(data)):
        c = msg[i]
        if c:
            for j in range(1, len(g)):
                msg[i + j] ^= _mul(g[j], c)
    return msg[len(data):]


def _codewords(text: bytes):
    for v in range(1, 11):
        cap = sum(n * d for n, d in BLOCKS[v])
        if 4 + 8 + 8 * len(text) <= cap * 8:
            break
    else:
        raise ToolError("text too long for a QR code up to version 10")
    bits = []

    def put(val, n):
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)
    put(4, 4)
    put(len(text), 8)
    for b in text:
        put(b, 8)
    put(0, min(4, cap * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < cap:
        data.append(pad)
        pad = 0x11 if pad == 0xEC else 0xEC
    blocks, pos = [], 0
    for n, d in BLOCKS[v]:
        for _ in range(n):
            blocks.append(data[pos:pos + d])
            pos += d
    ecs = [_rs(b, EC[v]) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(EC[v]):
        for e in ecs:
            out.append(e[i])
    return v, out


def _matrix(text: bytes):
    v, cw = _codewords(text)
    size = v * 4 + 17
    m = [[False] * size for _ in range(size)]
    fn = [[False] * size for _ in range(size)]

    def setf(x, y, dark):
        m[y][x] = dark
        fn[y][x] = True
    for i in range(size):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    setf(x, y, max(abs(dx), abs(dy)) not in (2, 4))
    al = ALIGN[v]
    na = len(al)
    for i in range(na):
        for j in range(na):
            if (i == 0 and j == 0) or (i == 0 and j == na - 1) or (i == na - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    setf(al[i] + dx, al[j] + dy, max(abs(dx), abs(dy)) != 1)

    def draw_format(mask):
        d = (0 << 3) | mask       # level M = 00
        r = d
        for _ in range(10):
            r = (r << 1) ^ ((r >> 9) * 0x537)
        b = ((d << 10) | r) ^ 0x5412
        bit = lambda i: ((b >> i) & 1) != 0  # noqa: E731
        for i in range(6):
            setf(8, i, bit(i))
        setf(8, 7, bit(6))
        setf(8, 8, bit(7))
        setf(7, 8, bit(8))
        for i in range(9, 15):
            setf(14 - i, 8, bit(i))
        for i in range(8):
            setf(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            setf(8, size - 15 + i, bit(i))
        setf(8, size - 8, True)
    draw_format(0)
    if v >= 7:
        r = v
        for _ in range(12):
            r = (r << 1) ^ ((r >> 11) * 0x1F25)
        b = (v << 12) | r
        for i in range(18):
            dark = ((b >> i) & 1) != 0
            a, c = size - 11 + i % 3, i // 3
            setf(a, c, dark)
            setf(c, a, dark)
    i = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                up = ((right + 1) & 2) == 0
                y = size - 1 - vert if up else vert
                if not fn[y][x] and i < len(cw) * 8:
                    m[y][x] = ((cw[i >> 3] >> (7 - (i & 7))) & 1) != 0
                    i += 1
        right -= 2
    masks = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
             lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
             lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
             lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]

    def apply(k):
        for y in range(size):
            for x in range(size):
                if not fn[y][x] and masks[k](x, y):
                    m[y][x] = not m[y][x]

    def penalty():
        p = 0
        lines = [row[:] for row in m] + [[m[y][x] for y in range(size)] for x in range(size)]
        pat1 = [True, False, True, True, True, False, True, False, False, False, False]
        pat2 = pat1[::-1]
        for ln in lines:
            run = 1
            for k in range(1, size + 1):
                if k < size and ln[k] == ln[k - 1]:
                    run += 1
                else:
                    if run >= 5:
                        p += 3 + run - 5
                    run = 1
            for k in range(size - 10):
                seg = ln[k:k + 11]
                if seg == pat1 or seg == pat2:
                    p += 40
        for y in range(size - 1):
            for x in range(size - 1):
                c = m[y][x]
                if c == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    p += 3
        dark = sum(sum(1 for c in row if c) for row in m)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        return p + k * 10
    best, best_p = 0, None
    for k in range(8):
        apply(k)
        draw_format(k)
        pk = penalty()
        if best_p is None or pk < best_p:
            best, best_p = k, pk
        apply(k)
    apply(best)
    draw_format(best)
    return m


def png(text: str, scale: int = 8, border: int = 4) -> bytes:
    m = _matrix(text.encode("utf-8"))
    n = len(m)
    w = (n + 2 * border) * scale
    rows = bytearray()
    for py in range(w):
        rows.append(0)
        y = py // scale - border
        for px in range(w):
            x = px // scale - border
            dark = 0 <= x < n and 0 <= y < n and m[y][x]
            rows.append(0 if dark else 255)

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, w, 8, 0, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


@tool("nfse_qr", "Makes the QR code of an NFS-e's official consultation link (the DANFSe's QR) as a PNG: saved in the "
      "add-on's folder and answered as base64 for a PDF.",
      props={"chave": prop("string", "The 50-digit access key."),
             "scale": prop("integer", "Pixels per module (default 8).", minimum=2, maximum=20)},
      required=("chave",), module="nfse")
def nfse_qr(a: dict) -> dict:
    chave = "".join(ch for ch in str(a.get("chave") or "") if ch.isdigit())
    if len(chave) != 50:
        raise ToolError("chave must be the 50-digit access key of the NFS-e", field="chave")
    url = CONSULTA % chave
    data = png(url, int(a.get("scale") or 8))
    folder = os.path.join(data_dir(), "notas")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, chave + "-qr.png")
    with open(path, "wb") as f:
        f.write(data)
    return {"url": url, "png": path, "bytes": len(data), "base64": base64.b64encode(data).decode()}
