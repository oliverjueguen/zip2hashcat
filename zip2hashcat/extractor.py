"""
Core ZIP parser and hashcat hash extractor.

Supports:
  - ZipCrypto (PKZIP legacy) -> $pkzip$ format (hashcat modes 17200-17230)
  - WinZip AES-128/192/256   -> $zip2$ format (hashcat mode 13600)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, List

# ── ZIP constants ────────────────────────────────────────────

LOCAL_FILE_HEADER_SIG = b"PK\x03\x04"
CENTRAL_DIR_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"

COMP_STORED = 0
COMP_AES = 99

FLAG_ENCRYPTED = 0x0001

AES_EXTRA_FIELD_ID = 0x9901
AES_PWD_VERIFY_SIZE = 2
AES_AUTH_CODE_SIZE = 10
AES_SALT_SIZE = {1: 8, 2: 12, 3: 16}


@dataclass
class ZipEntry:
    """Single file entry in a ZIP archive."""
    filename: str
    compression_method: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    file_data_offset: int
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
    def checksum_byte(self) -> str:
        return format((self.crc32 >> 24) & 0xFF, "02x")

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


def parse_zip(filepath: str) -> ZipFileInfo:
    """Parse a ZIP file and extract entry metadata."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"ZIP file not found: {filepath}")

    info = ZipFileInfo(path=filepath)
    with open(filepath, "rb") as f:
        data = f.read()

    eocd_pos = data.rfind(EOCD_SIG)
    if eocd_pos == -1:
        raise ValueError("Not a valid ZIP file (no EOCD record found)")

    (
        _disk_num, _disk_cd, _entries_on_disk, total_entries,
        _cd_size, cd_offset, _comment_len,
    ) = struct.unpack_from("<HHHHIIH", data, eocd_pos + 4)

    pos = cd_offset
    for _ in range(total_entries):
        if pos + 46 > len(data) or data[pos:pos + 4] != CENTRAL_DIR_SIG:
            break

        (
            _ver_made, _ver_needed, flags, compression,
            _mod_time, _mod_date, crc32, comp_size, uncomp_size,
            fname_len, extra_len, comment_len,
            _disk_start, _int_attr, _ext_attr, local_header_offset,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, pos + 4)

        filename = data[pos + 46:pos + 46 + fname_len].decode("utf-8", errors="replace")
        extra_data = data[pos + 46 + fname_len:pos + 46 + fname_len + extra_len]
        aes_strength, aes_actual_comp = _parse_aes_extra(extra_data)

        file_data_offset = 0
        if local_header_offset + 30 <= len(data):
            if data[local_header_offset:local_header_offset + 4] == LOCAL_FILE_HEADER_SIG:
                lf_len, le_len = struct.unpack_from("<HH", data, local_header_offset + 26)
                file_data_offset = local_header_offset + 30 + lf_len + le_len

        info.entries.append(ZipEntry(
            filename=filename, compression_method=compression, flags=flags,
            crc32=crc32, compressed_size=comp_size, uncompressed_size=uncomp_size,
            file_data_offset=file_data_offset,
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


def _extract_zipcrypto_hash(filepath: Path, entries: List[ZipEntry]) -> str:
    """Generate $pkzip$ hash for ZipCrypto."""
    with open(filepath, "rb") as f:
        data = f.read()

    parts = []
    for entry in entries:
        encrypted = data[entry.file_data_offset:entry.file_data_offset + entry.compressed_size]
        if len(encrypted) < 12:
            continue
        dt = 1 if entry.is_compressed else 2
        cs = entry.checksum_byte
        tc = format(entry.crc32 & 0xFFFF, "04x")
        parts.append(
            f"{dt}*2"
            f"*{entry.compressed_size:x}*{entry.uncompressed_size:x}"
            f"*{entry.crc32_hex}*{entry.file_data_offset:x}*0"
            f"*{entry.compression_method:x}"
            f"*{len(encrypted):x}"
            f"*{cs}*{tc}"
            f"*{encrypted.hex()}"
        )

    if not parts:
        raise ValueError("Could not extract valid ZipCrypto data")

    return f"$pkzip${len(parts)}*1*" + "*".join(parts) + "*$/pkzip$"


def _extract_aes_hash(filepath: Path, entries: List[ZipEntry]) -> str:
    """Generate $zip2$ hash for WinZip AES."""
    with open(filepath, "rb") as f:
        data = f.read()

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
    """
    filepath = Path(filepath)
    zip_info = parse_zip(filepath)
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
        hash_str = _extract_aes_hash(filepath, encrypted)
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
        hash_str = _extract_zipcrypto_hash(filepath, zc)
    else:
        raise ValueError(f"Unsupported encryption: {zip_info.encryption_type}")

    return hash_str, info
