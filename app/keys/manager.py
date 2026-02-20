"""KeyManager: simple filesystem-backed key storage with safe defaults."""
from pathlib import Path
import os
import stat


class KeyManager:
    def __init__(self, store_dir: str | Path = "./keystore"):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _secure_write(self, path: Path, data: bytes, mode: int = 0o600):
        with open(path, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, mode)
        except Exception:
            # On Windows chmod is limited; best-effort only
            pass

    def save_private_key(self, name: str, data: bytes):
        p = self.store_dir / f"{name}.pem"
        self._secure_write(p, data)
        return p

    def load_private_key(self, name: str):
        p = self.store_dir / f"{name}.pem"
        if not p.exists():
            raise FileNotFoundError(p)
        return p.read_bytes()
