import hashlib
import os
import secrets

def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Deriva una contraseña usando PBKDF2-HMAC-SHA256.
    Devuelve la clave derivada y el salt utilizado (Requisito RS1).
    """
    if salt is None:
        salt = os.urandom(16) # Genera un salt aleatorio único de 16 bytes
    
    # Derivación robusta de la clave
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000 # Número de iteraciones (mitiga ataques de fuerza bruta)
    )
    return key, salt

def verify_password(stored_key: bytes, stored_salt: bytes, provided_password: str) -> bool:
    """
    Verifica si la contraseña proporcionada coincide con la guardada usando tiempo constante.
    """
    key, _ = hash_password(provided_password, stored_salt)
    # Requisito RS4: Comparación en tiempo constante para mitigar Timing Attacks
    return secrets.compare_digest(stored_key, key)