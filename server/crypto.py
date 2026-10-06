import hashlib
import os
import hmac

"""
RS1(a):Devuelve la clave derivada y el salt utilizado
Deriva una contraseña usando PBKDF2-HMAC-SHA256. 
"""
def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16) # Genera un salt aleatorio único de 16 bytes
    
    # Derivación robusta de la clave
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000 # Número de iteraciones (RS1(b))
    )
    return key, salt

#RS4: Verifica si la contraseña proporcionada coincide con la guardada usando tiempo constante.
def verify_password(stored_key: bytes, stored_salt: bytes, provided_password: str) -> bool:
    key, _ = hash_password(provided_password, stored_salt)
    #RS4
    return hmac.compare_digest(stored_key, key)

def generate_mac_key() -> bytes:
    return os.urandom(32)

def generate_hmac_sha256(secret_key: bytes, message: str) -> str:
    return hmac.new(secret_key, message.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_hmac_sha256(secret_key: bytes, message: str, signature: str) -> bool:
    expected_signature = generate_hmac_sha256(secret_key, message)
    return hmac.compare_digest(expected_signature, signature)