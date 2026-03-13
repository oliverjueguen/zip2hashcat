#!/usr/bin/env python3
"""Generate zip2hashcat.py standalone script from package source.

Run this script after modifying the package to keep zip2hashcat.py in sync:

    python scripts/build_standalone.py

The generated file is a single self-contained Python script with no imports
from the zip2hashcat package — suitable for deployment without installation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "zip2hashcat"
OUTPUT = ROOT / "zip2hashcat.py"

SHEBANG = "#!/usr/bin/env python3\n"

HEADER = '''\
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
'''

# Patterns to strip from module sources when inlining
_INTERNAL_IMPORTS = re.compile(
    r"^from zip2hashcat(?:\.\w+)? import .*\n", flags=re.MULTILINE
)
_FUTURE_IMPORT = re.compile(
    r"^from __future__ import annotations\n", flags=re.MULTILINE
)


def _strip_module_docstring(source: str) -> str:
    """Remove leading triple-quoted module docstring (if any)."""
    stripped = source.lstrip()
    for quote in ('"""', "'''"):
        if stripped.startswith(quote):
            end = stripped.find(quote, len(quote))
            if end != -1:
                return stripped[end + len(quote):].lstrip("\n")
    return source


def _read_module(path: Path, strip_internal_imports: bool = False) -> str:
    source = path.read_text(encoding="utf-8")
    source = _strip_module_docstring(source)
    source = _FUTURE_IMPORT.sub("", source)
    if strip_internal_imports:
        source = _INTERNAL_IMPORTS.sub("", source)
    return source.strip()


def build() -> None:
    init_src = (PKG / "__init__.py").read_text(encoding="utf-8")
    extractor_src = _read_module(PKG / "extractor.py")
    cli_src = _read_module(PKG / "cli.py", strip_internal_imports=True)

    # Extract __version__ line from __init__.py
    version_match = re.search(r'^(__version__ = .+)$', init_src, re.MULTILINE)
    if not version_match:
        print("ERROR: could not find __version__ in __init__.py", file=sys.stderr)
        sys.exit(1)
    version_line = version_match.group(1)

    parts = [
        SHEBANG,
        "from __future__ import annotations\n\n",
        HEADER,
        "# " + "-" * 76 + "\n",
        "# Standalone build — generated from the package source by scripts/build_standalone.py\n",
        "# To regenerate: python scripts/build_standalone.py\n",
        "# " + "-" * 76 + "\n\n",
        f"{version_line}\n\n",
        "# -- extractor --\n\n",
        extractor_src,
        "\n\n",
        "# -- cli --\n\n",
        cli_src,
        "\n\n",
        'if __name__ == "__main__":\n',
        "    main()\n",
    ]

    output = "".join(parts)
    OUTPUT.write_text(output, encoding="utf-8")
    print(f"Written: {OUTPUT}  ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build()
