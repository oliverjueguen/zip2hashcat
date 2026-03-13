#!/usr/bin/env python3
from __future__ import annotations

"""
zip2hashcat — Extract ZIP password hashes in native hashcat format.

Like zip2john, but for hashcat. No dependencies. No John required.

Quick install:
    wget https://raw.githubusercontent.com/oliverjueguen/zip2hashcat/main/zip2hashcat.py
    chmod +x zip2hashcat.py
    ./zip2hashcat.py secret.zip

Usage:
    ./zip2hashcat.py secret.zip
    ./zip2hashcat.py secret.zip -o hash.txt
    ./zip2hashcat.py secret.zip -q | hashcat -m 17200 -a 0 - wordlist.txt
    ./zip2hashcat.py *.zip --json
"""
# ----------------------------------------------------------------------------
# AUTO-GENERATED -- do not edit by hand.
# Run:  python scripts/build_standalone.py
# ----------------------------------------------------------------------------

__version__ = "1.1.0"

# -- extractor --

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, List

# ── ZIP constants ────────────────────────────────────────────

LOCAL_FILE_HEADER_SIG = b"PK\x03\x04"
CENTRAL_DIR_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"

COMP_STORED = 0
COMP_AES = 99

FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008  # sizes/CRC written after data; check byte from mod_time

AES_EXTRA_FIELD_ID = 0x9901
AES_PWD_VERIFY_SIZE = 2
AES_AUTH_CODE_SIZE = 10
AES_SALT_SIZE = {1: 8, 2: 12, 3: 16}

ZIP64_EXTRA_FIELD_ID = 0x0001

# Sentinel values that indicate ZIP64 extension is needed
_ZIP64_SENTINEL_2 = 0xFFFF
_ZIP64_SENTINEL_4 = 0xFFFFFFFF


@dataclass
class ZipEntry:
    """Single file entry in a ZIP archive."""
    filename: str
    compression_method: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    file_data_offset: int       # absolute offset of first encrypted byte
    local_header_offset: int = 0  # absolute offset of PK\x03\x04 signature
    mod_time: int = 0
    aes_strength: Optional[int] = None
    aes_actual_compression: Optional[int] = None

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def is_aes(self) -> bool:
        return self.compression_method == COMP_AES and self.aes_strength is not None

    @property
    def is_zipcrypto(self) -> bool:
        return self.is_encrypted and not self.is_aes

    @property
    def is_compressed(self) -> bool:
        if self.is_aes:
            return self.aes_actual_compression != COMP_STORED
        return self.compression_method != COMP_STORED

    @property
    def check4(self) -> str:
        """4-char (2-byte) checksum matching zip2john's $pkzip$ CS field.

        zip2john source:
          FLAG_LOCAL_SIZE_UNKNOWN (bit 3) → use mod_time both bytes
          otherwise                       → use top 2 bytes of CRC32

        Format: sprintf(cs, "%02x%02x", high_byte, low_byte)
        """
        if self.flags & FLAG_DATA_DESCRIPTOR:
            # streaming mode: check bytes come from mod_time
            return format((self.mod_time >> 8) & 0xFF, "02x") + format(self.mod_time & 0xFF, "02x")
        # normal mode: check bytes come from top 2 bytes of CRC32
        return format((self.crc32 >> 24) & 0xFF, "02x") + format((self.crc32 >> 16) & 0xFF, "02x")

    @property
    def checksum_byte(self) -> str:
        """Single check byte (high byte of check4). For display/testing purposes."""
        return self.check4[:2]

    @property
    def crc32_hex(self) -> str:
        return format(self.crc32, "08x")


@dataclass
class ZipFileInfo:
    """Parsed ZIP file information."""
    path: Path
    entries: List[ZipEntry] = field(default_factory=list)
    encryption_type: str = "none"

    @property
    def encrypted_entries(self) -> List[ZipEntry]:
        return [e for e in self.entries if e.is_encrypted]


def _parse_aes_extra(extra_data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Parse AES extra field (0x9901)."""
    offset = 0
    while offset + 4 <= len(extra_data):
        header_id, data_size = struct.unpack_from("<HH", extra_data, offset)
        offset += 4
        if header_id == AES_EXTRA_FIELD_ID and data_size >= 7:
            _ver, _vendor, strength, actual_comp = struct.unpack_from(
                "<HHBh", extra_data, offset
            )
            return strength, actual_comp
        offset += data_size
    return None, None


def _parse_zip64_extra(extra_data: bytes, need_uncomp: bool, need_comp: bool,
                       need_offset: bool) -> Tuple[int, int, int]:
    """Parse ZIP64 extended information extra field (0x0001).

    Returns (uncompressed_size, compressed_size, local_header_offset).
    Only parses fields that were sentinel (0xFFFFFFFF) in the standard record.
    """
    offset = 0
    while offset + 4 <= len(extra_data):
        header_id, data_size = struct.unpack_from("<HH", extra_data, offset)
        offset += 4
        if header_id == ZIP64_EXTRA_FIELD_ID:
            field_offset = offset
            uncomp, comp, lh_offset = 0, 0, 0
            if need_uncomp and field_offset + 8 <= offset + data_size:
                uncomp = struct.unpack_from("<Q", extra_data, field_offset)[0]
                field_offset += 8
            if need_comp and field_offset + 8 <= offset + data_size:
                comp = struct.unpack_from("<Q", extra_data, field_offset)[0]
                field_offset += 8
            if need_offset and field_offset + 8 <= offset + data_size:
                lh_offset = struct.unpack_from("<Q", extra_data, field_offset)[0]
            return uncomp, comp, lh_offset
        offset += data_size
    return 0, 0, 0


def _parse_zip_bytes(data: bytes, filepath: Path) -> ZipFileInfo:
    """Parse ZIP bytes and extract entry metadata."""
    info = ZipFileInfo(path=filepath)

    eocd_pos = data.rfind(EOCD_SIG)
    if eocd_pos == -1:
        raise ValueError("Not a valid ZIP file (no EOCD record found)")

    (
        _disk_num, _disk_cd, _entries_on_disk, total_entries,
        _cd_size, cd_offset, _comment_len,
    ) = struct.unpack_from("<HHHHIIH", data, eocd_pos + 4)

    # ZIP64: check sentinel values and look for ZIP64 EOCD
    if total_entries == _ZIP64_SENTINEL_2 or cd_offset == _ZIP64_SENTINEL_4:
        zip64_pos = data.rfind(ZIP64_EOCD_SIG)
        if zip64_pos != -1 and zip64_pos + 56 <= len(data):
            # ZIP64 EOCD: signature(4) + size_of_zip64_eocd(8) + ver_made(2) +
            # ver_needed(2) + disk_num(4) + disk_cd(4) + entries_on_disk(8) +
            # total_entries(8) + cd_size(8) + cd_offset(8)
            total_entries, _cd_size, cd_offset = struct.unpack_from(
                "<QQQ", data, zip64_pos + 24
            )

    pos = cd_offset
    for _ in range(total_entries):
        if pos + 46 > len(data) or data[pos:pos + 4] != CENTRAL_DIR_SIG:
            break

        (
            _ver_made, _ver_needed, flags, compression,
            mod_time, _mod_date, crc32, comp_size, uncomp_size,
            fname_len, extra_len, comment_len,
            _disk_start, _int_attr, _ext_attr, local_header_offset,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, pos + 4)

        filename = data[pos + 46:pos + 46 + fname_len].decode("utf-8", errors="replace")
        extra_data = data[pos + 46 + fname_len:pos + 46 + fname_len + extra_len]

        # Resolve ZIP64 sentinel values from extra field
        need_uncomp = uncomp_size == _ZIP64_SENTINEL_4
        need_comp = comp_size == _ZIP64_SENTINEL_4
        need_offset = local_header_offset == _ZIP64_SENTINEL_4
        if need_uncomp or need_comp or need_offset:
            z64_uncomp, z64_comp, z64_offset = _parse_zip64_extra(
                extra_data, need_uncomp, need_comp, need_offset
            )
            if need_uncomp:
                uncomp_size = z64_uncomp
            if need_comp:
                comp_size = z64_comp
            if need_offset:
                local_header_offset = z64_offset

        aes_strength, aes_actual_comp = _parse_aes_extra(extra_data)

        file_data_offset = 0
        if local_header_offset + 30 <= len(data):
            if data[local_header_offset:local_header_offset + 4] == LOCAL_FILE_HEADER_SIG:
                lf_len, le_len = struct.unpack_from("<HH", data, local_header_offset + 26)
                file_data_offset = local_header_offset + 30 + lf_len + le_len

        info.entries.append(ZipEntry(
            filename=filename, compression_method=compression, flags=flags,
            crc32=crc32, compressed_size=comp_size, uncompressed_size=uncomp_size,
            file_data_offset=file_data_offset, local_header_offset=local_header_offset,
            mod_time=mod_time,
            aes_strength=aes_strength, aes_actual_compression=aes_actual_comp,
        ))
        pos += 46 + fname_len + extra_len + comment_len

    enc = info.encrypted_entries
    if not enc:
        info.encryption_type = "none"
    elif all(e.is_aes for e in enc):
        info.encryption_type = "aes"
    elif all(e.is_zipcrypto for e in enc):
        info.encryption_type = "zipcrypto"
    else:
        info.encryption_type = "mixed"

    return info


def parse_zip(filepath: str) -> ZipFileInfo:
    """Parse a ZIP file and extract entry metadata."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"ZIP file not found: {filepath}")
    with open(filepath, "rb") as f:
        data = f.read()
    return _parse_zip_bytes(data, filepath)


def _extract_zipcrypto_hash(data: bytes, entries: List[ZipEntry]) -> str:
    """Generate $pkzip$ hash for ZipCrypto, matching zip2john's format exactly.

    Format per entry (from zip2john.c):
      DT * MT * CL * UL * CR * OF * OX * CT * DL * CS * DA
      DT = 1 (compressed) or 2 (stored)
      MT = 0 (magic type, always 0 for zipcrypto)
      CL = compressed length (hex)
      UL = uncompressed length (hex)
      CR = CRC32 (hex)
      OF = offset to local file header PK\\x03\\x04 (hex)
      OX = extra offset from OF to first encrypted byte (hex)
      CT = compression method (hex)
      DL = encrypted data length (hex)
      CS = 4-char checksum (2 bytes):
           FLAG_DATA_DESCRIPTOR set → mod_time high byte + mod_time low byte
           otherwise                → CRC32 byte3 + CRC32 byte2
      DA = encrypted bytes (hex)

    Overall: $pkzip$C*2* ... *$/pkzip$
      C  = number of entries
      2  = check_bytes count (zip2john always uses 2-byte check)
    """
    parts = []
    for entry in entries:
        # compressed_size from Central Directory is always correct (even for
        # data descriptor ZIPs where local header sizes may be zero)
        encrypted = data[entry.file_data_offset:entry.file_data_offset + entry.compressed_size]
        if len(encrypted) < 12:
            continue
        dt = 1 if entry.is_compressed else 2
        # OX = distance from local header to first encrypted byte
        ox = entry.file_data_offset - entry.local_header_offset
        parts.append(
            f"{dt}*0"
            f"*{entry.compressed_size:x}*{entry.uncompressed_size:x}"
            f"*{entry.crc32_hex}*{entry.local_header_offset:x}*{ox:x}"
            f"*{entry.compression_method:x}"
            f"*{len(encrypted):x}"
            f"*{entry.check4}"
            f"*{encrypted.hex()}"
        )

    if not parts:
        raise ValueError("Could not extract valid ZipCrypto data")

    return f"$pkzip${len(parts)}*2*" + "*".join(parts) + "*$/pkzip$"


def _extract_aes_hash(data: bytes, entries: List[ZipEntry]) -> str:
    """Generate $zip2$ hash for WinZip AES from already-read bytes.

    Uses the smallest entry to minimize hash size while remaining crackable.
    """
    entry = min(entries, key=lambda e: e.compressed_size)
    salt_size = AES_SALT_SIZE.get(entry.aes_strength, 16)
    off = entry.file_data_offset

    salt = data[off:off + salt_size]
    pwd_verify = data[off + salt_size:off + salt_size + AES_PWD_VERIFY_SIZE]
    auth_off = off + entry.compressed_size - AES_AUTH_CODE_SIZE
    auth_code = data[auth_off:auth_off + AES_AUTH_CODE_SIZE]
    payload_len = auth_off - (off + salt_size + AES_PWD_VERIFY_SIZE)

    return (
        f"$zip2$*0*{entry.aes_strength}*0"
        f"*{salt.hex()}*{pwd_verify.hex()}"
        f"*{payload_len:x}**{auth_code.hex()}"
        f"*$/zip2$"
    )


def extract_hash(filepath: str) -> Tuple[str, dict]:
    """Extract hashcat-compatible hash from a ZIP file.

    Returns (hash_string, info_dict).
    Reads the file only once.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"ZIP file not found: {filepath}")

    with open(filepath, "rb") as f:
        data = f.read()

    zip_info = _parse_zip_bytes(data, filepath)
    encrypted = zip_info.encrypted_entries

    if not encrypted:
        raise ValueError(f"ZIP file is not password-protected: {filepath}")

    info = {
        "file": str(filepath),
        "total_entries": len(zip_info.entries),
        "encrypted_entries": len(encrypted),
        "encryption_type": zip_info.encryption_type,
        "filenames": [e.filename for e in encrypted],
    }

    if zip_info.encryption_type == "aes":
        entry = min(encrypted, key=lambda e: e.compressed_size)
        info["aes_strength"] = {1: 128, 2: 192, 3: 256}.get(entry.aes_strength, 0)
        info["hashcat_mode"] = 13600
        info["hashcat_name"] = "WinZip AES"
        hash_str = _extract_aes_hash(data, encrypted)
    elif zip_info.encryption_type in ("zipcrypto", "mixed"):
        zc = [e for e in encrypted if e.is_zipcrypto]
        has_comp = any(e.is_compressed for e in zc)
        has_uncomp = any(not e.is_compressed for e in zc)
        if len(zc) == 1:
            mode = 17200 if has_comp else 17210
            name = "PKZIP (Compressed)" if has_comp else "PKZIP (Uncompressed)"
        elif has_comp and has_uncomp:
            mode, name = 17225, "PKZIP (Mixed Multi-File)"
        elif has_comp:
            mode, name = 17220, "PKZIP (Compressed Multi-File)"
        else:
            mode, name = 17210, "PKZIP (Uncompressed)"
        info["hashcat_mode"] = mode
        info["hashcat_name"] = name
        hash_str = _extract_zipcrypto_hash(data, zc)
    else:
        raise ValueError(f"Unsupported encryption: {zip_info.encryption_type}")

    return hash_str, info

# -- cli --

import argparse
import json
import sys


_USE_COLOR = sys.stdout.isatty()

BOLD    = "\033[1m"  if _USE_COLOR else ""
DIM     = "\033[2m"  if _USE_COLOR else ""
RED     = "\033[91m" if _USE_COLOR else ""
GREEN   = "\033[92m" if _USE_COLOR else ""
CYAN    = "\033[96m" if _USE_COLOR else ""
MAGENTA = "\033[95m" if _USE_COLOR else ""
RESET   = "\033[0m"  if _USE_COLOR else ""

AES_BITS = {1: "128", 2: "192", 3: "256"}


def _banner():
    print(f"\n{BOLD}{CYAN}+========================================+{RESET}")
    print(f"{BOLD}{CYAN}|  zip2hashcat v{__version__:<25s}|{RESET}")
    print(f"{BOLD}{CYAN}+========================================+{RESET}\n")


def _show_info(info):
    print(f"  {BOLD}File:{RESET}         {info['file']}")
    print(f"  {BOLD}Entries:{RESET}      {info['total_entries']} total, {info['encrypted_entries']} encrypted")
    print(f"  {BOLD}Encryption:{RESET}   {info['encryption_type'].upper()}")
    if "aes_strength" in info:
        print(f"  {BOLD}AES:{RESET}          {info['aes_strength']}-bit")
    print(f"  {BOLD}Hashcat mode:{RESET} {GREEN}-m {info['hashcat_mode']}{RESET} ({info['hashcat_name']})")
    print(f"  {BOLD}Files:{RESET}")
    for fn in info["filenames"]:
        print(f"    {DIM}• {fn}{RESET}")
    print()


def _show_commands(info, hash_file="hash.txt"):
    m = info["hashcat_mode"]
    print(f"  {BOLD}{MAGENTA}Hashcat command:{RESET}")
    print(f"  hashcat -m {m} -a 0 {hash_file} <wordlist>")
    print()
    print(f"  {BOLD}{MAGENTA}With rules:{RESET}")
    print(f"  hashcat -m {m} -a 0 {hash_file} <wordlist> -r <rules>")
    print()
    print(f"  {BOLD}{MAGENTA}Brute-force (8 chars):{RESET}")
    print(f"  hashcat -m {m} -a 3 {hash_file} ?a?a?a?a?a?a?a?a")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="zip2hashcat",
        description="Extract ZIP password hashes in hashcat-compatible format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zip2hashcat secret.zip
  zip2hashcat secret.zip -o hash.txt
  zip2hashcat secret.zip -q | hashcat -m 17200 -a 0 - rockyou.txt
  zip2hashcat *.zip -q > hashes.txt
  zip2hashcat secret.zip --json
  zip2hashcat secret.zip --info
        """,
    )
    parser.add_argument("zipfiles", nargs="+", help="Path(s) to password-protected ZIP file(s)")
    parser.add_argument("-o", "--output", help="Save hash(es) to file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output the hash (for piping)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--info", action="store_true", help="Show ZIP encryption info only")
    parser.add_argument("-V", "--version", action="version", version=f"zip2hashcat {__version__}")

    args = parser.parse_args()

    # ── --info mode ──────────────────────────────────────────
    if args.info:
        _banner()
        for zipfile in args.zipfiles:
            try:
                zip_info = parse_zip(zipfile)
            except (FileNotFoundError, ValueError) as e:
                print(f"{RED}Error:{RESET} {e}", file=sys.stderr)
                continue
            print(f"  {BOLD}File:{RESET} {zipfile}")
            print(f"  {BOLD}Total entries:{RESET} {len(zip_info.entries)}")
            print(f"  {BOLD}Encryption:{RESET} {zip_info.encryption_type.upper()}\n")
            for i, entry in enumerate(zip_info.entries):
                enc = f"{GREEN}encrypted{RESET}" if entry.is_encrypted else f"{DIM}not encrypted{RESET}"
                detail = ""
                if entry.is_aes:
                    detail = f"AES-{AES_BITS.get(entry.aes_strength, '?')}"
                elif entry.is_zipcrypto:
                    detail = "ZipCrypto"
                comp = "deflated" if entry.is_compressed else "stored"
                print(f"  [{i + 1}] {entry.filename}")
                print(f"      {enc} {detail} | {comp} | CRC: {entry.crc32_hex}")
                print(f"      Size: {entry.uncompressed_size} -> {entry.compressed_size} bytes\n")
        return

    # ── Extract hashes ────────────────────────────────────────
    results = []
    errors = False
    for zipfile in args.zipfiles:
        try:
            hash_str, info = extract_hash(zipfile)
            results.append((hash_str, info))
        except (FileNotFoundError, ValueError) as e:
            print(f"{RED}Error:{RESET} {e}", file=sys.stderr)
            errors = True

    if not results:
        sys.exit(1)

    # ── --json mode ───────────────────────────────────────────
    if args.json:
        output = []
        for hash_str, info in results:
            entry = {**info, "hash": hash_str}
            output.append(entry)
        print(json.dumps(output, indent=2))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
                f.write("\n")
        return

    # ── --quiet mode ──────────────────────────────────────────
    if args.quiet:
        for hash_str, _ in results:
            print(hash_str)
        if args.output:
            with open(args.output, "w") as f:
                for hash_str, _ in results:
                    f.write(hash_str + "\n")
        return

    # ── Normal mode ───────────────────────────────────────────
    _banner()
    for hash_str, info in results:
        _show_info(info)

        if args.output:
            with open(args.output, "a") as f:
                f.write(hash_str + "\n")
            print(f"  {GREEN}✓ Hash written to:{RESET} {args.output}\n")
            _show_commands(info, args.output)
        else:
            print(f"  {BOLD}Hash:{RESET}")
            if len(hash_str) > 100:
                print(f"  {hash_str[:80]}...")
                print(f"  {DIM}(full hash: {len(hash_str)} chars){RESET}")
            else:
                print(f"  {hash_str}")
            print()
            _show_commands(info)
            print(f"  {DIM}Tip: use -o hash.txt to save directly to a file{RESET}\n")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
