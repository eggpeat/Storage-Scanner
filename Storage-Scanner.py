#!/usr/bin/env python3
"""
Storage Scanner - a disk usage analyzer for Windows and macOS.

Pick a drive or folder and it scans recursively, then shows every folder and
file in a tree sorted by size, with a percentage bar so the space hogs jump out.

This file is intentionally a thin entry point (kept at this path/name for
build.bat and .github/workflows/build.yml, which pass it straight to
PyInstaller) — the actual implementation lives in the storage_scanner/
package alongside it.

Run:  python Storage-Scanner.py [--cli <path> [--format json|csv] [--output FILE]]
"""

import sys

# Headless flags are dispatched here, BEFORE importing storage_scanner.app:
# app.py is the Tkinter GUI and imports tkinter unconditionally, so routing
# through it would make --cli/--priv-scan/--mft-scan require a GUI toolkit
# they never use. The conditions mirror app.main()'s own dispatch exactly
# (kept there for direct `from storage_scanner.app import main` callers);
# if one changes, change the other.
if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--priv-scan":
        from storage_scanner.priv_scan_cli import run_priv_scan
        run_priv_scan(sys.argv[2])
    elif len(sys.argv) >= 2 and sys.argv[1] == "--cli":
        from storage_scanner.cli import run_cli
        sys.exit(run_cli(sys.argv[2:]))
    elif len(sys.argv) >= 2 and sys.argv[1] == "--mft-scan":
        from storage_scanner.mft_scan_cli import run_mft_scan
        sys.exit(run_mft_scan(sys.argv[2:]))
    else:
        try:
            from storage_scanner.app import main
        except ModuleNotFoundError as exc:
            if exc.name != "tkinter":
                raise
            sys.exit(
                "Storage Scanner's GUI needs Tkinter, which isn't installed "
                "(e.g. `sudo apt install python3-tk` on Debian/Ubuntu). "
                "The headless scan works without it: "
                "python Storage-Scanner.py --cli <path> [--format json|csv] [--output FILE]"
            )
        main()
