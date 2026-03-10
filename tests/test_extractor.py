"""Tests for zip2hashcat."""

import subprocess

import pytest

from zip2hashcat.extractor import extract_hash, parse_zip


@pytest.fixture
def zipcrypto_single(tmp_path):
    txt = tmp_path / "secret.txt"
    txt.write_text("This is secret content for testing purposes")
    zipf = tmp_path / "test.zip"
    subprocess.run(["zip", "-P", "test123", str(zipf), str(txt)], cwd=str(tmp_path), capture_output=True)
    return zipf


@pytest.fixture
def zipcrypto_multi(tmp_path):
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"
    f1.write_text("First secret file content here " * 20)
    f2.write_text("Second secret file content here " * 20)
    zipf = tmp_path / "test.zip"
    subprocess.run(["zip", "-P", "test123", str(zipf), str(f1), str(f2)], cwd=str(tmp_path), capture_output=True)
    return zipf


@pytest.fixture
def zipcrypto_stored(tmp_path):
    txt = tmp_path / "stored.txt"
    txt.write_text("Content stored without compression")
    zipf = tmp_path / "test.zip"
    subprocess.run(["zip", "-P", "test123", "-0", str(zipf), str(txt)], cwd=str(tmp_path), capture_output=True)
    return zipf


@pytest.fixture
def aes_zip(tmp_path):
    txt = tmp_path / "secret.txt"
    txt.write_text("AES encrypted secret content")
    zipf = tmp_path / "test.zip"
    r = subprocess.run(["7z", "a", "-tzip", "-mem=AES256", "-ptest123", str(zipf), str(txt)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("7z not available")
    return zipf


@pytest.fixture
def no_password_zip(tmp_path):
    txt = tmp_path / "public.txt"
    txt.write_text("Not a secret")
    zipf = tmp_path / "test.zip"
    subprocess.run(["zip", str(zipf), str(txt)], cwd=str(tmp_path), capture_output=True)
    return zipf


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


class TestExtractHash:
    def test_zipcrypto_format(self, zipcrypto_single):
        h, info = extract_hash(str(zipcrypto_single))
        assert h.startswith("$pkzip$") and h.endswith("$/pkzip$")
        assert info["hashcat_mode"] == 17200

    def test_multi_format(self, zipcrypto_multi):
        h, info = extract_hash(str(zipcrypto_multi))
        assert h.startswith("$pkzip$2*")
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
        assert parts[2] == "3"        # AES-256
        assert len(parts[4]) == 32    # 16-byte salt
        assert len(parts[5]) == 4     # 2-byte verify
        assert parts[7] == ""         # DF empty

    def test_no_password_error(self, no_password_zip):
        with pytest.raises(ValueError, match="not password-protected"):
            extract_hash(str(no_password_zip))

    def test_consistent(self, zipcrypto_single):
        h1, _ = extract_hash(str(zipcrypto_single))
        h2, _ = extract_hash(str(zipcrypto_single))
        assert h1 == h2


class TestCLI:
    def test_basic(self, zipcrypto_single):
        r = subprocess.run(["zip2hashcat", str(zipcrypto_single)], capture_output=True, text=True)
        assert r.returncode == 0
        assert "-m 17200" in r.stdout

    def test_quiet(self, zipcrypto_single):
        r = subprocess.run(["zip2hashcat", str(zipcrypto_single), "-q"], capture_output=True, text=True)
        out = r.stdout.strip()
        assert out.startswith("$pkzip$") and "\n" not in out

    def test_output_file(self, zipcrypto_single, tmp_path):
        outf = tmp_path / "hash.txt"
        subprocess.run(["zip2hashcat", str(zipcrypto_single), "-o", str(outf)], capture_output=True)
        assert outf.read_text().strip().startswith("$pkzip$")

    def test_info(self, zipcrypto_multi):
        r = subprocess.run(["zip2hashcat", str(zipcrypto_multi), "--info"], capture_output=True, text=True)
        assert "ZIPCRYPTO" in r.stdout

    def test_error(self, no_password_zip):
        r = subprocess.run(["zip2hashcat", str(no_password_zip)], capture_output=True, text=True)
        assert r.returncode != 0
