from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path


SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def should_skip(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in SKIP_DIRS for part in rel.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    return False


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: make_installer_archive.py <portable_dir> <out_zip>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    out_zip = Path(sys.argv[2]).resolve()
    if not root.is_dir():
        print(f"portable dir not found: {root}", file=sys.stderr)
        return 1
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    if out_zip.exists():
        out_zip.unlink()

    files = [p for p in root.rglob("*") if p.is_file() and not should_skip(p, root)]
    total = sum(p.stat().st_size for p in files)
    written = 0
    print(f"archiving {len(files)} files, {total / (1024 ** 3):.2f} GiB from {root}")
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as zf:
        for index, path in enumerate(files, 1):
            arcname = path.relative_to(root).as_posix()
            zf.write(path, arcname)
            written += path.stat().st_size
            if index == 1 or index % 250 == 0 or index == len(files):
                print(f"[{index}/{len(files)}] {written / (1024 ** 3):.2f}/{total / (1024 ** 3):.2f} GiB")
    print(f"wrote {out_zip} ({out_zip.stat().st_size / (1024 ** 3):.2f} GiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
