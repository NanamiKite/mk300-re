#!/usr/bin/env python3
"""Offline MK300 frame encoder/decoder. No USB, MIDI, network or flash writes.

00 59: recovered from this MK300_073 binary; not tested on hardware.
00 32: external M-EFCS captures, https://github.com/jpfaria/mvave/blob/main/docs/protocol.md
"""
import argparse
import json
from functools import reduce
from operator import xor


def seven_bit(data):
    data = bytes(data)
    if any(v > 127 for v in data):
        raise ValueError('SysEx content must contain only 7-bit bytes')
    return data


def component_frame(component, ctrl1, ctrl2, payload=b'', device=1):
    if device not in (0, 1) or not 0 <= component < 16:
        raise ValueError('This binary accepts device 0/1, component 0..15')
    if len(payload) > 247:
        raise ValueError('Firmware frame buffer is 256 bytes; payload limit is 247')
    body = seven_bit(bytes([0, 0x59, device, component, ctrl1, ctrl2]) + payload)
    return b'\xf0' + body + bytes([reduce(xor, body, 0), 0xf7])


def component_decode(frame):
    if len(frame) < 9 or frame[:3] != b'\xf0\x00\x59' or frame[-1] != 0xf7:
        raise ValueError('Invalid 00 59 framing')
    seven_bit(frame[1:-1])
    if len(frame) > 256 or frame[3] not in (0, 1) or frame[4] >= 16:
        raise ValueError('Unsupported size, device or component')
    if reduce(xor, frame[1:-2], 0) != frame[-2]:
        raise ValueError('XOR checksum mismatch')
    return dict(protocol='00 59', device=frame[3], component=frame[4],
                ctrl1=frame[5], ctrl2=frame[6], payload=frame[7:-2].hex(' '))


def u14(value):
    if not 0 <= value <= 16383:
        raise ValueError('Unsigned 14-bit value out of range')
    return bytes([value & 127, value >> 7])


def parameter_i14(value):
    """Absolute PARAM values: signed 14-bit two's complement, not delta bias."""
    if not -8192 <= value <= 8191:
        raise ValueError('Signed 14-bit value out of range')
    return u14(value & 0x3fff)


def pack7(payload):
    value = int.from_bytes(payload, 'little')
    return bytes((value >> i) & 127 for i in range(0, len(payload)*8, 7))


def digits7(value):
    if not 0 <= value < 1 << 28:
        raise ValueError('28-bit header field out of range')
    return bytes((value >> (7*i)) & 127 for i in range(4))


def efcs_frame(space, offset, length, payload=b'', write=False):
    if not 0 <= space <= 15 or not 0 <= length < 1 << 24:
        raise ValueError('Invalid memory space or length')
    if write and len(payload) != length:
        raise ValueError('Write payload length mismatch')
    if not write and payload:
        raise ValueError('Read requests have no payload')
    field = digits7(offset)
    command = 0x41 + (len(payload) * 8 if write else 0)
    sub = digits7((length << 4) | space)
    check_fields = ((length << 8) | (space << 4)).to_bytes(4, 'little')
    ck = (0xfb - sum(payload) - sum(field) - sum(check_fields)) & 255
    return (b'\xf0\x00\x32' + bytes([9 if write else 13]) + digits7(command)
            + b'\x02' + field + sub + pack7(payload+bytes([ck])) + b'\xf7')


def self_check():
    # Independent published captures, rather than encode/decode self-consistency alone.
    vectors = [
        (efcs_frame(2, 0, 86), 'f0 00 32 0d 41 00 00 00 02 00 00 00 00 62 0a 00 00 05 01 f7'),
        (efcs_frame(1, 0, 448), 'f0 00 32 0d 41 00 00 00 02 00 00 00 00 01 38 00 00 2a 00 f7'),
        (efcs_frame(1, 0x18, 2, bytes([60, 0]), True), 'f0 00 32 09 51 00 00 00 02 18 00 00 00 21 00 00 00 3c 00 54 04 f7'),
        (efcs_frame(1, 0x2c, 1, b'\x00', True), 'f0 00 32 09 49 00 00 00 02 2c 00 00 00 11 00 00 00 00 7c 02 f7'),
        (efcs_frame(2, 0x3c, 1, b'\x01', True), 'f0 00 32 09 49 00 00 00 02 3c 00 00 00 12 00 00 00 01 3a 02 f7'),
        (component_frame(9, 1, 0), 'f0 00 59 01 09 01 00 50 f7'),
    ]
    for result, expected in vectors:
        if result != bytes.fromhex(expected):
            raise AssertionError((result.hex(), expected))
    component_decode(vectors[-1][0])
    bad = bytearray(vectors[-1][0]); bad[-2] ^= 1
    try:
        component_decode(bad)
    except ValueError:
        pass
    else:
        raise AssertionError('Corrupt XOR frame was accepted')
    if parameter_i14(-60) != bytes([68, 127]):
        raise AssertionError('Signed parameter encoding mismatch')
    print('PASS: 5 external M-EFCS capture vectors; static 00 59 vector; corruption rejection; signed14')
    print('No hardware communication was performed.')


def integer(text):
    return int(text, 0)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    subs = ap.add_subparsers(dest='cmd', required=True)
    subs.add_parser('self-check')
    subs.add_parser('version-query')
    p = subs.add_parser('component')
    p.add_argument('component', type=integer)
    p.add_argument('ctrl1', type=integer)
    p.add_argument('ctrl2', type=integer)
    p.add_argument('--data', default='', help='Space-separated hex bytes')
    p = subs.add_parser('decode')
    p.add_argument('hex')
    p = subs.add_parser('efcs-read')
    p.add_argument('space', type=integer)
    p.add_argument('offset', type=integer)
    p.add_argument('length', type=integer)
    p = subs.add_parser('cc')
    p.add_argument('number', type=integer)
    p.add_argument('value', type=integer)
    p.add_argument('--channel', type=int, default=1)
    a = ap.parse_args()
    try:
        if a.cmd == 'self-check':
            self_check()
        elif a.cmd == 'decode':
            print(json.dumps(component_decode(bytes.fromhex(a.hex)), indent=2))
        else:
            if a.cmd == 'version-query':
                data = component_frame(9, 1, 0)
            elif a.cmd == 'component':
                data = component_frame(a.component, a.ctrl1, a.ctrl2, bytes.fromhex(a.data))
            elif a.cmd == 'efcs-read':
                data = efcs_frame(a.space, a.offset, a.length)
            else:
                if not 1 <= a.channel <= 16:
                    raise ValueError('MIDI channel must be 1..16')
                data = bytes([0xb0+a.channel-1])+seven_bit([a.number, a.value])
            print(data.hex(' ').upper())
    except (ValueError, OverflowError) as exc:
        ap.error(str(exc))
