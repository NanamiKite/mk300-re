#!/usr/bin/env python3
"""Read-only AC792N FWSC extraction and evidence export (Python standard library).

Format reference: https://github.com/kagaimiq/jl-misctools
This implementation validates CRCs and keeps offsets in a JSON manifest.
Never communicates with a device or modifies the input firmware.
"""
import argparse
import binascii
import csv
import hashlib
import json
import re
import struct
from pathlib import Path


def crc(data):
    return binascii.crc_hqx(data, 0)


def decode(data, key=0xffff):
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= key & 255
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 65535
    return bytes(out)


def check(actual, expected, label):
    if actual != expected:
        raise ValueError(f'{label}: expected {expected:#x}, got {actual:#x}')


def bounded(data, off, size):
    if off < 0 or size < 0 or off + size > len(data):
        raise ValueError(f'Out of bounds: {off:#x} + {size:#x} > {len(data):#x}')
    return data[off:off + size]


def cstr(data):
    return data.split(b'\0')[0].rstrip(b'\xff').decode('ascii')


def save(root, name, data):
    if Path(name).name != name or name in ('.', '..'):
        raise ValueError(f'Unsafe entry name: {name!r}')
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_bytes(data)


def entry(data, pos):
    raw = bounded(data, pos, 32)
    hcrc, dcrc, off, size, flags, reserved, last, name = struct.unpack('<HHIIBBH16s', raw)
    check(crc(raw[2:]), hcrc, f'JLFS header {pos:#x}')
    return dict(name=cstr(name), header_offset=pos, offset=off, size=size,
                flags=flags, reserved=reserved, last=last, data_crc=dcrc,
                header_crc=hcrc, header_crc_ok=True)


def make_elf(data, base):
    # Synthetic ELF wrapper, not original symbols or recovered source.
    names = b'\0.text\0.shstrtab\0'
    noff = 52 + len(data)
    shoff = (noff + len(names) + 3) & ~3
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    hdr = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 241, 1, base, 0,
                      shoff, 0, 52, 0, 0, 40, 3, 2)
    sections = bytes(40)
    sections += struct.pack('<10I', 1, 1, 6, base, 52, len(data), 0, 0, 2, 0)
    sections += struct.pack('<10I', 7, 3, 0, 0, noff, len(names), 0, 0, 1, 0)
    return (hdr + data + names).ljust(shoff, b'\0') + sections


def decode_boot(payload):
    out = bytearray(payload)
    index, count = 0, 1
    while index < count:
        pos = index * 16
        hdr = decode(bounded(out, pos, 16))
        check(crc(hdr[:14]), int.from_bytes(hdr[14:], 'little'), 'BANKCB header CRC')
        bankid, size, load, offset, expected, _ = struct.unpack('<HHIIHH', hdr)
        if index == 0:
            count = bankid
            if not 1 <= count <= len(out) // 16:
                raise ValueError('Invalid BANKCB bank count')
        data = decode(bounded(out, offset, size))
        check(crc(data), expected, 'BANKCB data CRC')
        out[pos:pos+16] = hdr
        out[offset:offset+size] = data
        index += 1
    return bytes(out)


def export_evidence(app, base, out):
    def string_at(va):
        off = va - base
        if not 0 <= off < len(app):
            return None
        raw = app[off:off + 256].split(b'\0')[0]
        if raw and all(c in (10, 13) or 32 <= c < 127 for c in raw):
            return raw.decode('ascii')
        return None

    strings = []
    for m in re.finditer(rb'[\x20-\x7e]{4,}', app):
        strings.append(dict(offset=f'0x{m.start():08x}',
                            address=f'0x{base+m.start():08x}', text=m.group().decode()))
    with (out / 'strings.tsv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['offset', 'address', 'text'], delimiter='\t')
        w.writeheader()
        w.writerows(strings)

    # MK300_073-specific, evidence-backed table locations. Abort on other versions.
    if b'MK300_073\0' not in app:
        return
    cc_ranges = [(0xfb5fc, 6), (0xfc5b4, 8), (0xfe0cc, 6),
                 (0xfef44, 14), (0xff104, 8)]
    cc = []
    modes = ['Toggle', 'Momentary', 'Continuous', 'Mapped']
    for off, count in cc_ranges:
        for n in range(count):
            pos = off + n * 16
            number, label, mode, hint = struct.unpack_from('<4I', app, pos)
            name = string_at(label)
            if not name or number > 127 or mode > 3:
                raise ValueError(f'Unexpected CC table at {pos:#x}')
            cc.append(dict(cc=number, label=name, ui_mode=modes[mode],
                           hint=string_at(hint) if hint else '', offset=hex(pos)))
    cc.sort(key=lambda item: item['cc'])
    (out / 'midi_cc.json').write_text(json.dumps(cc, ensure_ascii=False, indent=2)+'\n')

    pages = []
    # Struct fields remain unnamed unless their semantics are established.
    for off in range(0xe7e84, 0xe8680, 4):
        name_ptr, size, color, flags, zero1, zero2, ptr = struct.unpack_from('<7I', app, off)
        name = string_at(name_ptr)
        if (name and len(name) < 24 and 16 <= size <= 4096 and
                zero1 == zero2 == 0 and flags <= 0x100 and base <= ptr < base+len(app)):
            pages.append(dict(name=name, name_pointer_offset=hex(off),
                              struct_fields=[hex(v) for v in (size, color, flags, ptr)],
                              callbacks_before_name=[hex(v) for v in struct.unpack_from('<5I', app, off-20)],
                              callbacks_after_fields=[hex(v) for v in struct.unpack_from('<9I', app, off+28)]))
    (out / 'gui_pages.json').write_text(json.dumps(pages, indent=2)+'\n')


def unpack(source, out):
    raw = source.read_bytes()
    # FWSC inserts 20 bytes: one after every 47 bytes in the first 960 bytes.
    header = b''.join(bounded(raw, n*48, 47) for n in range(20))
    hdr = decode(header[:64])
    hcrc, lcrc, image_size, count, unknown, align, chip = struct.unpack('<HHIHHI48s', hdr)
    check(crc(hdr[2:]), hcrc, 'UFW header CRC')
    check(len(raw)-20, image_size, 'UFW image size')
    table = bounded(header, 64, count*80)
    check(crc(table), lcrc, 'UFW encrypted entry-list CRC')
    meta = dict(input=str(source), size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                chip=cstr(chip), header_crc_ok=True, entry_list_crc_ok=True,
                payload_offset_bias=20, container_entries=[])
    flash = None
    for i in range(count):
        row = decode(table[i*80:(i+1)*80])
        typ, index, expected, unk, offset, size, padded, aux, name = struct.unpack('<HHHHIII44s16s', row)
        name = cstr(name)
        payload = bounded(raw, offset+20, size)
        save(out/'container', name, payload)
        meta['container_entries'].append(dict(name=name, type=typ, index=index,
            ufw_offset=offset, fwsc_offset=offset+20, size=size, padded_size=padded,
            crc16=expected, raw_crc_ok=crc(payload)==expected))
        if typ == 0:
            flash = bytearray(payload)
    if flash is None:
        raise ValueError('No flash.bin entry')

    fh = decode(flash[:32])
    check(crc(fh[2:]), int.from_bytes(fh[:2], 'little'), 'Flash header CRC')
    # VID and PID fields are plaintext in the stored flash header.
    meta['flash'] = dict(vid=cstr(flash[4:8]), pid=cstr(flash[16:32]),
        flash_size=struct.unpack_from('<I', fh, 8)[0], header_crc_ok=True, top_entries=[])
    flash[:32] = fh[:4] + flash[4:8] + fh[8:16] + flash[16:32]
    appbase = key = None
    for pos in range(32, 512, 32):
        flash[pos:pos+32] = decode(flash[pos:pos+32])
        e = entry(flash, pos)
        meta['flash']['top_entries'].append(e)
        if e['name'] == 'app_dir_head':
            appbase = e['offset']
        elif not e['flags'] & 0x10:
            payload = bounded(flash, e['offset'], e['size'])
            if e['name'] == 'uboot.boot':
                payload = decode_boot(payload)
                flash[e['offset']:e['offset']+e['size']] = payload
                e['bank_header_and_data_crc_ok'] = True
            check(crc(payload), e['data_crc'], f"{e['name']} data CRC")
            e['data_crc_ok'] = True
            save(out/'top', e['name'], payload)
            if e['name'] == 'isd_config.ini':
                check(crc(payload[:32]), int.from_bytes(payload[32:34], 'little'), 'Chipkey CRC')
                threshold = sum(payload[:16]) & 255
                threshold = 0xaa if threshold >= 0xe0 else 0x55 if threshold <= 0x10 else threshold
                key = sum(1 << n for n in range(16) if payload[16+n] ^ payload[15-n] < threshold)
        if e['last']:
            break
    if appbase is None or key is None:
        raise ValueError('Missing application base or chipkey')
    meta['flash'].update(app_base=appbase, chipkey=hex(key))
    for e in meta['container_entries']:
        if e['raw_crc_ok']:
            e['crc_ok'] = True
            e['encoding'] = 'stored'
            continue
        payload = bounded(raw, e['fwsc_offset'], e['size'])
        decoded = b''.join(decode(payload[i:i+32], key ^ ((e['ufw_offset']+i) >> 2))
                           for i in range(0, len(payload), 32))
        check(crc(decoded), e['crc16'], f"{e['name']} SFC-decoded package CRC")
        save(out/'container_encoded', e['name'], payload)
        save(out/'container', e['name'], decoded)
        e['encoding'] = 'sfc32_chipkey_xor_ufw_offset_div4'
        e['crc_ok'] = True
    # Only decrypt the physically present application area, in 32-byte blocks.
    for pos in range(appbase, len(flash), 32):
        flash[pos:pos+32] = decode(flash[pos:pos+32], key ^ ((pos-appbase) >> 2))
    area = entry(flash, appbase)
    meta['flash']['application_area'] = area
    meta['flash']['application_entries'] = []
    app = None
    for pos in range(appbase+32, appbase+4096, 32):
        e = entry(flash, pos)
        meta['flash']['application_entries'].append(e)
        if e['flags'] == 0x82:
            payload = bounded(flash, appbase+e['offset'], e['size'])
            check(crc(payload), e['data_crc'], f"{e['name']} application CRC")
            e['data_crc_ok'] = True
            e['sha256'] = hashlib.sha256(payload).hexdigest()
            save(out/'files', e['name'], payload)
            if e['name'] == 'app.bin':
                app = payload
                base = area['offset']
        if e['last']:
            break
    if app is None:
        raise ValueError('No app.bin')
    tailpos = appbase + area['size']
    ext = entry(flash, tailpos)
    meta['flash']['extended_reserved'] = ext
    meta['flash']['reserved_subentries'] = [entry(flash, p) for p in range(tailpos+32, tailpos+ext['size'],32)]
    save(out, 'decrypted_flash.bin', flash)
    save(out, 'app.elf', make_elf(app, base))
    export_evidence(app, base, out)
    (out/'manifest.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2)+'\n')
    print(f"{meta['chip']}: {len(meta['container_entries'])} entries, all package CRCs OK")
    print(f'app.bin: {len(app)} bytes, CRC OK, entry {base:#010x}')
    print(f'Evidence exported to {out}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input', type=Path)
    ap.add_argument('--out', type=Path, default=Path('analysis/extracted'))
    args = ap.parse_args()
    if args.out.exists():
        ap.error('Output directory already exists; choose a new --out directory')
    args.out.mkdir(parents=True)
    unpack(args.input, args.out)
