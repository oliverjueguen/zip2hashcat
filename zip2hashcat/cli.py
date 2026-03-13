"""zip2hashcat CLI — like zip2john but for hashcat."""

from __future__ import annotations

import argparse
import json
import sys

from zip2hashcat import __version__
from zip2hashcat.extractor import extract_hash, parse_zip

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
