from __future__ import annotations

import shutil
import struct
import sys
from pathlib import Path


MAGIC = b"CIAINSTPKG0001\r\n"
TRAILER = struct.Struct("<16sQQ")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: append_installer_payload.py <stub_exe> <payload_zip> <out_exe>", file=sys.stderr)
        return 2
    stub = Path(sys.argv[1]).resolve()
    payload = Path(sys.argv[2]).resolve()
    out = Path(sys.argv[3]).resolve()
    if not stub.is_file():
        print(f"stub not found: {stub}", file=sys.stderr)
        return 1
    if not payload.is_file():
        print(f"payload not found: {payload}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    offset = stub.stat().st_size
    size = payload.stat().st_size
    with out.open("wb") as dst:
        with stub.open("rb") as src:
            shutil.copyfileobj(src, dst, length=16 * 1024 * 1024)
        with payload.open("rb") as src:
            shutil.copyfileobj(src, dst, length=16 * 1024 * 1024)
        dst.write(TRAILER.pack(MAGIC, offset, size))
    print(f"wrote {out} ({out.stat().st_size / (1024 ** 3):.2f} GiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
