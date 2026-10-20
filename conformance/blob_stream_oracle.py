#!/usr/bin/env python3
"""Independent stdlib wire construction; no Rust encoder or bindings.

Code-path/language diversity only, not an independent-team interoperability claim.
The checked-in corpus is consumed by the production Rust codecs' tests.
"""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent


def u16(n):
    return struct.pack('>H', n)


def request(offset=0, total=32768, length=16384, direction=2):
    return (b'ASM\x01\xa1' + bytes([direction]) + b'\x01' * 32
            + b'\x02' * 33 + struct.pack('>QQI', total, offset, length)
            + b'\x03' * 32)


def schedule(*entries):
    return b'ABRS\x01' + u16(len(entries)) + b''.join(entries)


def digest(value):
    return hashlib.sha256(b'ASTER/blob-ranges-stream/schedule/v1\0' + value).digest()


def corpus():
    rows = []

    def add(ok, kind, name, wire):
        rows.append(('ACCEPT' if ok else 'REJECT', kind, name, wire.hex()))

    first, second = request(), request(16384)
    base = schedule(first, second)
    for name, wire in [('empty', schedule()), ('two', base),
                       ('resume', schedule(second)),
                       ('maximum', schedule(*(request(i * 16384, 64 * 16384)
                                              for i in range(64))))]:
        add(True, 'schedule', name, wire)
    for name, wire in [('duplicate', schedule(first, first)), ('reversed', schedule(second, first)),
                       ('gap', schedule(request(0, 65536), request(32768, 65536))),
                       ('total-conflict', schedule(first, request(16384, 32769))),
                       ('direction', schedule(request(direction=1))),
                       ('zero-length', schedule(request(length=0))),
                       ('oversize-range', schedule(request(length=16385))),
                       ('noncanonical', schedule(request(length=1))),
                       ('count-limit', b'ABRS\x01' + u16(65) + first * 65),
                       ('count-mismatch', b'ABRS\x01' + u16(3) + first + second),
                       ('truncated', base[:-1]), ('trailing', base + b'\0'),
                       ('version', b'ABRS\x02' + base[5:]),
                       ('source', schedule(first, second[:6] + b'\x04' + second[7:])),
                       ('proof', schedule(first, second[:-1] + b'\x04'))]:
        add(False, 'schedule', name, wire)
    # Data/terminal vectors bind this single one-byte request, responder direction.
    single = schedule(request(total=1, length=1))
    binding = digest(single)
    data = (b'ABRD\x01' + binding + u16(0) + b'ASM\x01\xa2'
            + single[12:98] + b'\x01' + struct.pack('>I', 1) + b'Z')
    unavailable = data[:130] + b'\x02' + struct.pack('>I', 0)
    add(True, 'data', 'one-byte', data)
    add(True, 'data', 'unavailable', unavailable)
    for name, wire in [('truncated', data[:-1]), ('trailing', data + b'\0'),
                       ('digest', data[:5] + b'\0' * 32 + data[37:]),
                       ('index', data[:37] + u16(1) + data[39:]),
                       ('direction', data[:44] + b'\x01' + data[45:]),
                       ('source', data[:45] + b'\x04' + data[46:]),
                       ('object', data[:77] + b'\x01' + data[78:]),
                       ('status', data[:130] + b'\x03' + data[131:]),
                       ('unavailable-payload', data[:130] + b'\x02' + data[131:]),
                       ('payload-length', data[:131] + struct.pack('>I', 2) + b'Z')]:
        add(False, 'data', name, wire)
    terminal = b'ABRE\x01' + binding + u16(1)
    add(True, 'terminal', 'complete', terminal)
    for name, wire in [('truncated', terminal[:-1]), ('trailing', terminal + b'\0'),
                       ('digest', terminal[:5] + b'\0' * 32 + terminal[37:]),
                       ('count', terminal[:37] + u16(0)),
                       ('kind', b'ABRD' + terminal[4:])]:
        add(False, 'terminal', name, wire)
    return '# aster-blob-stream-records/v1\toracle=python-stdlib\n' + ''.join(
        '\t'.join(row) + '\n' for row in rows)


def profile5_composite_corpus():
    rows = [
        ('ACCEPT', 'one-segment', b'ASD1' + struct.pack('>I', 2) + b'\xa1\xa2\xb1\xb2\xb3'),
        ('REJECT', 'wrong-magic', b'ASD2' + struct.pack('>I', 2) + b'\xa1\xa2\xb1'),
        ('REJECT', 'zero-header', b'ASD1' + struct.pack('>I', 0) + b'\xb1'),
        ('REJECT', 'oversized-header', b'ASD1' + struct.pack('>I', 2049) + b'\xa1'),
        ('REJECT', 'truncated-length', b'ASD1\0\0\0'),
        ('REJECT', 'truncated-header', b'ASD1' + struct.pack('>I', 3) + b'\xa1\xa2'),
    ]
    return '# aster-profile5-composite-data-record/v1\toracle=python-stdlib\n' + ''.join(
        '\t'.join((status, name, wire.hex())) + '\n'
        for status, name, wire in rows
    )


def main():
    offer = ('# aster-blob-ranges-stream-vectors/v1\tsemantic=7,8\toracle=python-stdlib\n'
             'ACCEPT\toffer-blob-stream-only-v1\t'
             '0105000501000100040100040003010001000201000100010200020001\n')
    outputs = {
        'blob-ranges-stream-v1.tsv': offer,
        'blob-stream-records-v1.tsv': corpus(),
        'profile5-composite-data-record-v1.tsv': profile5_composite_corpus(),
    }
    for name, text in outputs.items():
        path = ROOT / 'vectors' / name
        if '--write' in sys.argv:
            path.write_text(text)
        else:
            assert path.read_text() == text, f'{path}: differs from independent construction'
    seed = ROOT.parent / 'fuzz/corpus/selected_frame_decode/blob-stream-only-offer-v1'
    seed_bytes = b'ASM\x01\xd1' + bytes.fromhex(offer.splitlines()[1].split('\t')[2])
    if '--write' in sys.argv:
        seed.write_bytes(seed_bytes)
    else:
        assert seed.read_bytes() == seed_bytes, 'fuzz offer seed differs'
    print('Blob stream oracle: all corpora and fuzz offer match independent Python construction')


if __name__ == '__main__':
    main()
