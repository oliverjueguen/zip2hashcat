"""Tests for zip2hashcat."""

import base64
import json
import shutil
import struct
import subprocess
import sys
import zlib

import pytest

from zip2hashcat.extractor import extract_hash, parse_zip, _parse_zip_bytes
from pathlib import Path

# Use the current Python interpreter to run the CLI, so it works regardless of
# whether 'zip2hashcat' is on PATH (e.g. Windows installs scripts off-PATH).
_CLI = [sys.executable, "-m", "zip2hashcat.cli"]


# ── Pure-Python ZipCrypto fixture builder ─────────────────────────────────────
# These helpers create valid ZipCrypto-encrypted ZIPs without any external tools,
# so tests run anywhere Python 3 is available.

def _crc32_byte(crc: int, byte: int) -> int:
    return zlib.crc32(bytes([byte]), crc) & 0xFFFFFFFF


def _zipcrypto_init(password: str):
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in password.encode("latin-1"):
        k0 = _crc32_byte(k0, c)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 0x08088405 + 1) & 0xFFFFFFFF
        k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def _ks(k2: int) -> int:
    t = (k2 | 2) & 0xFFFF
    return ((t * (t ^ 1)) >> 8) & 0xFF


def _key_update(k0, k1, k2, b):
    k0 = _crc32_byte(k0, b)
    k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
    k1 = (k1 * 0x08088405 + 1) & 0xFFFFFFFF
    k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def _zipcrypto_encrypt(plaintext: bytes, password: str, check_byte: int) -> bytes:
    k0, k1, k2 = _zipcrypto_init(password)
    # 12-byte encryption header: 11 null bytes + CRC check byte
    header = bytes(11) + bytes([check_byte])
    out = bytearray()
    for b in header:
        out.append(b ^ _ks(k2))
        k0, k1, k2 = _key_update(k0, k1, k2, b)
    for b in plaintext:
        out.append(b ^ _ks(k2))
        k0, k1, k2 = _key_update(k0, k1, k2, b)
    return bytes(out)


def _build_zipcrypto_zip(entries: list, password: str, use_data_descriptor: bool = False) -> bytes:
    """Build a ZIP with ZipCrypto-encrypted entries.

    entries: list of (content: bytes, filename: str, compress: bool)
    use_data_descriptor: if True, sets bit 3 (streaming mode); check byte = (mod_time>>8)&0xFF
    """
    local_parts = []
    meta = []
    offset = 0
    MOD_TIME = 0x5A3C  # arbitrary fixed mod_time for deterministic tests
    flags_base = 1 | (8 if use_data_descriptor else 0)

    for content, fname, compress in entries:
        if compress:
            comp_data = zlib.compress(content, 6)[2:-4]  # raw deflate
            method = 8
        else:
            comp_data = content
            method = 0
        crc = zlib.crc32(content) & 0xFFFFFFFF
        check = ((MOD_TIME >> 8) & 0xFF) if use_data_descriptor else ((crc >> 24) & 0xFF)
        enc = _zipcrypto_encrypt(comp_data, password, check)
        fn = fname.encode()
        # Local file header (30 bytes)
        lh = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, flags_base, method, MOD_TIME, 0, crc, len(enc), len(content), len(fn), 0,
        )
        local = lh + fn + enc
        local_parts.append(local)
        meta.append((crc, len(enc), len(content), method, fn, offset))
        offset += len(local)

    cd_parts = []
    for crc, csz, usz, method, fn, loffset in meta:
        # Central directory entry (46 bytes)
        cd = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, flags_base, method, MOD_TIME, 0,
            crc, csz, usz, len(fn), 0, 0, 0, 0, 0, loffset,
        )
        cd += fn
        cd_parts.append(cd)

    local_data = b"".join(local_parts)
    cd_data = b"".join(cd_parts)
    n = len(entries)
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, n, n, len(cd_data), len(local_data), 0
    )
    return local_data + cd_data + eocd


# ── Portable fixtures (no external tools needed) ──────────────────────────────

@pytest.fixture
def zipcrypto_single(tmp_path):
    zipf = tmp_path / "test.zip"
    data = _build_zipcrypto_zip(
        [(b"This is secret content for testing purposes", "secret.txt", True)],
        "test123",
    )
    zipf.write_bytes(data)
    return zipf


@pytest.fixture
def zipcrypto_stored(tmp_path):
    zipf = tmp_path / "test.zip"
    data = _build_zipcrypto_zip(
        [(b"Content stored without compression", "stored.txt", False)],
        "test123",
    )
    zipf.write_bytes(data)
    return zipf


@pytest.fixture
def zipcrypto_multi(tmp_path):
    zipf = tmp_path / "test.zip"
    data = _build_zipcrypto_zip(
        [
            (b"First secret file content here " * 20, "file1.txt", True),
            (b"Second secret file content here " * 20, "file2.txt", True),
        ],
        "test123",
    )
    zipf.write_bytes(data)
    return zipf


@pytest.fixture
def no_password_zip(tmp_path):
    """Unencrypted ZIP built with stdlib zipfile."""
    import zipfile
    zipf = tmp_path / "public.zip"
    with zipfile.ZipFile(zipf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("public.txt", "Not a secret")
    return zipf


# ── External-tool fixtures (skipped if tools unavailable) ─────────────────────

@pytest.fixture
def aes_zip(tmp_path):
    if not shutil.which("7z"):
        pytest.skip("7z not available")
    txt = tmp_path / "secret.txt"
    txt.write_text("AES encrypted secret content")
    zipf = tmp_path / "test.zip"
    r = subprocess.run(
        ["7z", "a", "-tzip", "-mem=AES256", "-ptest123", str(zipf), str(txt)],
        capture_output=True,
    )
    if r.returncode != 0:
        pytest.skip("7z failed to create AES zip")
    return zipf


# ── TestParseZip ──────────────────────────────────────────────────────────────

class TestParseZip:
    def test_zipcrypto(self, zipcrypto_single):
        info = parse_zip(str(zipcrypto_single))
        assert info.encryption_type == "zipcrypto"
        assert len(info.encrypted_entries) == 1

    def test_multi(self, zipcrypto_multi):
        info = parse_zip(str(zipcrypto_multi))
        assert len(info.encrypted_entries) == 2

    def test_stored(self, zipcrypto_stored):
        info = parse_zip(str(zipcrypto_stored))
        assert not info.encrypted_entries[0].is_compressed

    def test_aes(self, aes_zip):
        info = parse_zip(str(aes_zip))
        assert info.encryption_type == "aes"
        assert info.encrypted_entries[0].aes_strength == 3

    def test_no_password(self, no_password_zip):
        info = parse_zip(str(no_password_zip))
        assert info.encryption_type == "none"

    def test_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_zip("/nonexistent.zip")


# ── TestExtractHash ───────────────────────────────────────────────────────────

class TestExtractHash:
    def test_zipcrypto_format(self, zipcrypto_single):
        h, info = extract_hash(str(zipcrypto_single))
        assert h.startswith("$pkzip$") and h.endswith("$/pkzip$")
        assert info["hashcat_mode"] == 17200

    def test_zip2john_compatible_header(self, zipcrypto_single):
        """Hash must start with $pkzip$C*2* — matching zip2john's check_bytes=2."""
        h, _ = extract_hash(str(zipcrypto_single))
        assert h.startswith("$pkzip$1*2*"), f"Expected $pkzip$1*2*, got: {h[:20]}"

    def test_zip2john_entry_format(self, zipcrypto_single):
        """Per-entry format: DT*0*CL*UL*CR*OF*OX*CT*DL*CS4*DATA (matching zip2john)."""
        h, _ = extract_hash(str(zipcrypto_single))
        # strip wrapper: $pkzip$1*2* ... *$/pkzip$
        inner = h[len("$pkzip$1*2*"):-len("*$/pkzip$")]
        fields = inner.split("*")
        # DT: 1=compressed, 2=stored
        assert fields[0] in ("1", "2")
        # MT (magic type): always 0 in zip2john
        assert fields[1] == "0", f"MT should be 0, got {fields[1]}"
        # CS4: exactly 4 hex chars (2 bytes)
        cs4 = fields[9]
        assert len(cs4) == 4 and all(c in "0123456789abcdef" for c in cs4), \
            f"CS4 should be 4 hex chars, got '{cs4}'"

    def test_multi_format(self, zipcrypto_multi):
        h, info = extract_hash(str(zipcrypto_multi))
        assert h.startswith("$pkzip$2*2*")
        assert info["hashcat_mode"] == 17220

    def test_stored_format(self, zipcrypto_stored):
        _, info = extract_hash(str(zipcrypto_stored))
        assert info["hashcat_mode"] == 17210

    def test_aes_format(self, aes_zip):
        h, info = extract_hash(str(aes_zip))
        assert h.startswith("$zip2$") and h.endswith("$/zip2$")
        assert info["hashcat_mode"] == 13600
        assert info["aes_strength"] == 256

    def test_aes_structure(self, aes_zip):
        h, _ = extract_hash(str(aes_zip))
        parts = h.split("*")
        assert parts[2] == "3"        # AES-256 strength
        assert len(parts[4]) == 32    # 16-byte salt → 32 hex chars
        assert len(parts[5]) == 4     # 2-byte verify → 4 hex chars
        assert parts[7] == ""         # empty data field

    def test_no_password_error(self, no_password_zip):
        with pytest.raises(ValueError, match="not password-protected"):
            extract_hash(str(no_password_zip))

    def test_consistent(self, zipcrypto_single):
        h1, _ = extract_hash(str(zipcrypto_single))
        h2, _ = extract_hash(str(zipcrypto_single))
        assert h1 == h2


# ── TestEdgeCases ─────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_not_a_zip(self, tmp_path):
        f = tmp_path / "fake.zip"
        f.write_bytes(b"This is not a ZIP file")
        with pytest.raises(ValueError, match="no EOCD"):
            parse_zip(str(f))

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.zip"
        f.write_bytes(b"")
        with pytest.raises(ValueError):
            parse_zip(str(f))

    def test_truncated_zip(self, tmp_path):
        # Local header signature present but no EOCD
        f = tmp_path / "truncated.zip"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 26)
        with pytest.raises(ValueError, match="no EOCD"):
            parse_zip(str(f))

    def test_parse_zip_bytes_directly(self, zipcrypto_single):
        data = zipcrypto_single.read_bytes()
        info = _parse_zip_bytes(data, zipcrypto_single)
        assert info.encryption_type == "zipcrypto"
        assert len(info.encrypted_entries) == 1

    def test_check4_data_descriptor_flag(self, tmp_path):
        """When bit 3 set, check4 = full mod_time (2 bytes), matching zip2john TS_chk."""
        content = b"streaming mode content"
        data = _build_zipcrypto_zip(
            [(content, "file.txt", True)], "test123", use_data_descriptor=True
        )
        zipf = tmp_path / "test.zip"
        zipf.write_bytes(data)
        info = _parse_zip_bytes(data, zipf)
        entry = info.encrypted_entries[0]
        assert entry.flags & 0x0008, "bit 3 should be set"
        # zip2john: sprintf(cs, "%02x%02x", mod_time>>8, mod_time&0xFF)
        MOD_TIME = 0x5A3C
        expected = format(MOD_TIME >> 8, "02x") + format(MOD_TIME & 0xFF, "02x")
        assert entry.check4 == expected

    def test_check4_no_data_descriptor(self, zipcrypto_single):
        """Without bit 3, check4 = top 2 bytes of CRC32, matching zip2john CRC_chk."""
        data = zipcrypto_single.read_bytes()
        info = _parse_zip_bytes(data, zipcrypto_single)
        entry = info.encrypted_entries[0]
        assert not (entry.flags & 0x0008)
        # zip2john: sprintf(cs, "%02x%02x", (crc>>24)&0xff, (crc>>16)&0xff)
        expected = format((entry.crc32 >> 24) & 0xFF, "02x") + format((entry.crc32 >> 16) & 0xFF, "02x")
        assert entry.check4 == expected


# ── TestCLI ───────────────────────────────────────────────────────────────────

class TestCLI:
    def test_basic(self, zipcrypto_single):
        r = subprocess.run(
            [*_CLI, str(zipcrypto_single)], capture_output=True, text=True
        )
        assert r.returncode == 0
        assert "-m 17200" in r.stdout

    def test_quiet(self, zipcrypto_single):
        r = subprocess.run(
            [*_CLI, str(zipcrypto_single), "-q"], capture_output=True, text=True
        )
        out = r.stdout.strip()
        assert out.startswith("$pkzip$") and "\n" not in out

    def test_output_file(self, zipcrypto_single, tmp_path):
        outf = tmp_path / "hash.txt"
        subprocess.run(
            [*_CLI, str(zipcrypto_single), "-o", str(outf)], capture_output=True
        )
        assert outf.read_text().strip().startswith("$pkzip$")

    def test_info(self, zipcrypto_multi):
        r = subprocess.run(
            [*_CLI, str(zipcrypto_multi), "--info"], capture_output=True, text=True
        )
        assert "ZIPCRYPTO" in r.stdout

    def test_error_no_password(self, no_password_zip):
        r = subprocess.run(
            [*_CLI, str(no_password_zip)], capture_output=True, text=True
        )
        assert r.returncode != 0

    def test_multi_zip_quiet(self, zipcrypto_single, zipcrypto_multi):
        r = subprocess.run(
            [*_CLI, "-q", str(zipcrypto_single), str(zipcrypto_multi)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        lines = r.stdout.strip().splitlines()
        assert len(lines) == 2
        assert all(l.startswith("$pkzip$") for l in lines)

    def test_json_output(self, zipcrypto_single):
        r = subprocess.run(
            [*_CLI, "--json", str(zipcrypto_single)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list) and len(data) == 1
        assert data[0]["hashcat_mode"] == 17200
        assert data[0]["hash"].startswith("$pkzip$")

    def test_no_ansi_in_piped_output(self, zipcrypto_single):
        r = subprocess.run(
            [*_CLI, "-q", str(zipcrypto_single)],
            capture_output=True, text=True,
        )
        # When stdout is a pipe (not tty), no ANSI escape codes should appear
        assert "\033[" not in r.stdout
