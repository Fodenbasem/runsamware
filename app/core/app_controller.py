"""Controller that connects GUI with crypto and keys."""
from app.crypto.engine import CryptoEngine
from app.keys.manager import KeyManager
from app.utils.logger import setup_logging


class AppController:
    def __init__(self, *, keystore_dir: str = "./keystore", logs_dir: str = "./logs"):
        self.logger = setup_logging("novavault", logs_dir)
        self.crypto = CryptoEngine()
        self.keys = KeyManager(keystore_dir)

    def handle_encrypt(self):
        self.logger.info("Encrypt action received (stub)")
