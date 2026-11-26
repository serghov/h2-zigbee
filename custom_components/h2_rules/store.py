"""Rule sources kept as plain files in <config>/h2_rules/.

Per switch (named by its IEEE address with the colons replaced by dashes):
  <ieee>.c      the source text, the working copy
  <ieee>.bpf    the image that was last loaded onto the switch from here
  <ieee>.json   {"name", "saved", "uploaded", "crc", "length"}: when the source was saved,
                and the checksum and length of the image above

The files can be edited, copied and put under version control outside Home Assistant.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .const import MAX_IMAGE_BYTES, MAX_SOURCE_BYTES

_IEEE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){7}$")


def _base(directory: Path, ieee: str) -> Path:
    ieee = ieee.lower()
    if not _IEEE.match(ieee):
        raise ValueError("not an IEEE address")
    return directory / ieee.replace(":", "-")


def load(directory: Path, ieee: str) -> dict:
    base = _base(directory, ieee)
    out: dict = {"source": None, "meta": {}, "image": None}
    src = base.with_suffix(".c")
    if src.is_file():
        out["source"] = src.read_text(encoding="utf-8")
    meta = base.with_suffix(".json")
    if meta.is_file():
        try:
            out["meta"] = json.loads(meta.read_text(encoding="utf-8"))
        except ValueError:
            out["meta"] = {}
    image = base.with_suffix(".bpf")
    if image.is_file():
        out["image"] = image.read_bytes().hex()
    return out


def save(directory: Path, ieee: str, source: str | None, image_hex: str | None, meta: dict) -> dict:
    base = _base(directory, ieee)
    directory.mkdir(parents=True, exist_ok=True)
    if source is not None:
        data = source.encode("utf-8")
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("source too large")
        _write(base.with_suffix(".c"), data)
    if image_hex is not None:
        image = bytes.fromhex(image_hex)
        if len(image) > MAX_IMAGE_BYTES:
            raise ValueError("image too large")
        _write(base.with_suffix(".bpf"), image)
    old: dict = {}
    meta_file = base.with_suffix(".json")
    if meta_file.is_file():
        try:
            old = json.loads(meta_file.read_text(encoding="utf-8"))
        except ValueError:
            old = {}
    old.update({k: v for k, v in meta.items() if k in ("name", "saved", "uploaded", "crc", "length")})
    _write(meta_file, json.dumps(old, indent=2).encode("utf-8"))
    return old


def listing(directory: Path) -> list[dict]:
    out = []
    if not directory.is_dir():
        return out
    for src in sorted(directory.glob("*.c")):
        ieee = src.stem.replace("-", ":")
        if not _IEEE.match(ieee):
            continue
        meta = {}
        meta_file = src.with_suffix(".json")
        if meta_file.is_file():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except ValueError:
                meta = {}
        out.append({"ieee": ieee, "meta": meta})
    return out


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
