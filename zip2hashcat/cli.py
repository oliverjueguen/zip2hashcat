"""zip2hashcat CLI — like zip2john but for hashcat."""

from __future__ import annotations

import argparse
import sys

from zip2hashcat import __version__
from zip2hashcat.extractor import extract_hash, parse_zip

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

AES_BITS = {1: "128", 2: "192", 3: "256"}


def _banner():
    print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║  zip2hashcat v{__version__:<25s}║{RESET}")
    print(f"{BOLD}{CYAN}╚════════════════════════════════════════╝{RESET}\n")


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
    print(f"  hashcat -m {m} -a 0 {hash_file} /usr/share/wordlists/rockyou.txt")
    print()
    print(f"  {BOLD}{MAGENTA}With rules:{RESET}")
    print(f"  hashcat -m {m} -a 0 {hash_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule")
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
  zip2hashcat secret.zip --info
        """,
    )
    parser.add_argument("zipfile", help="Path to password-protected ZIP file")
    parser.add_argument("-o", "--output", help="Save hash to file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output the hash (for piping)")
    parser.add_argument("--info", action="store_true", help="Show ZIP encryption info only")
    parser.add_argument("-V", "--version", action="version", version=f"zip2hashcat {__version__}")

    args = parser.parse_args()

    if args.info:
        try:
            zip_info = parse_zip(args.zipfile)
        except (FileNotFoundError, ValueError) as e:
            print(f"{RED}Error:{RESET} {e}", file=sys.stderr)
            sys.exit(1)
        _banner()
        print(f"  {BOLD}File:{RESET} {args.zipfile}")
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

    try:
        hash_str, info = extract_hash(args.zipfile)
    except (FileNotFoundError, ValueError) as e:
        print(f"{RED}Error:{RESET} {e}", file=sys.stderr)
        sys.exit(1)

    if args.quiet:
        print(hash_str)
        return

    _banner()
    _show_info(info)

    if args.output:
        with open(args.output, "w") as f:
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


if __name__ == "__main__":
    main()
