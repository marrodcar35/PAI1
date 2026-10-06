import os
import sys  
import requests
import time

ruta_actual = os.path.dirname(os.path.abspath(__file__))
ruta_raiz = os.path.dirname(ruta_actual)
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)
from server.crypto import generate_hmac_sha256

BASE_URL = "http://127.0.0.1:8080/api/v1"

print("========================================")
print("1. INICIANDO SESIÓN")
print("========================================")
login_data = {
    "username": "usuario1", 
    "password": "123456"
}
login_response = requests.post(f"{BASE_URL}/login", json=login_data)
login_result = login_response.json()

print(f"Respuesta del servidor: {login_result}")

if login_response.status_code != 200:
    print("❌ Error en el login. Abortando.")
    exit()

session_token = login_result["session_token"]
mac_key_hex = login_result["mac_key"]


print("\n========================================")
print("2. PREPARANDO LA TRANSFERENCIA")
print("========================================")
tx_id = "tx-001"
origen = "ES12345678"
destino = "ES87654321"
cantidad = 150.50
moneda = "EUR"
timestamp = int(time.time())

# A. Concatenamos igual que lo hace el servidor
mensaje_a_firmar = f"{tx_id}{origen}{destino}{cantidad}{moneda}{timestamp}"

# B. Calculamos el MAC usando TU módulo crypto
mac_key_bytes = bytes.fromhex(mac_key_hex)
# ¡Aquí está el cambio! Usamos la función que creaste
mac_generado = generate_hmac_sha256(mac_key_bytes, mensaje_a_firmar)

print(f"Mensaje concatenado: {mensaje_a_firmar}")
print(f"Firma MAC generada:  {mac_generado}")

transfer_payload = {
    "session_token": session_token,
    "tx_id": tx_id,
    "origin_account": origen,
    "destination_account": destino,
    "amount": cantidad,
    "currency": moneda,
    "timestamp": timestamp,
    "mac": mac_generado
}

print("\n========================================")
print("3. ENVIANDO TRANSFERENCIA AL SERVIDOR")
print("========================================")
transfer_response = requests.post(f"{BASE_URL}/transfer", json=transfer_payload)

print(f"Código HTTP devuelto: {transfer_response.status_code}")
print(f"Respuesta del servidor: {transfer_response.json()}")