import hmac
import hashlib
import os
import time
import uuid
import json
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def hash_password(password: str) -> tuple[str, str]:
    """
    Genera un Salt aleatorio de 16 bytes y deriva el hash de la contraseña
    usando PBKDF2-HMAC-SHA256 con 100,000 iteraciones (RS1)[cite: 3].
    Devuelve la pareja (hash_hex, salt_hex) para guardar en la base de datos.
    """
    salt = os.urandom(16)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iter=100000,
    )
    key_hash = key.derive(password.encode('utf-8'))
    return key_hash.hex(), salt.hex()