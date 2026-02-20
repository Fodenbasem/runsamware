from pathlib import Path


def atomic_write(path: str | Path, data: bytes, mode: str = "wb"):
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, mode) as f:
        f.write(data)
    tmp.replace(p)
