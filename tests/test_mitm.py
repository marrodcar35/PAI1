import requests
import time
import hmac
import hashlib

BASE_URL = "http://127.0.0.1:8080/api/v1"

# Hacemos login para obtener una sesión válida
print("1. Iniciando sesión legítima...")
login_res = requests.post(f"{BASE_URL}/login", json={"username": "usuario1", "password": "Usuario1@"})
if login_res.status_code != 200:
    print("Error en login. Asegúrate de que el servidor está encendido.")
    exit()

session_data = login_res.json()
mac_key = bytes.fromhex(session_data["mac_key"])

# Preparamos una transferencia legítima de 50€
tx_id = "tx-mitm-001"
origen = "ES12345678"
destino = "ES87654321"
cantidad_legitima = 50.0
moneda = "EUR"
timestamp = int(time.time())
nonce = "nonce-falso-mitm-1234"

# Calculamos la firma MAC original
msg = f"{tx_id}{origen}{destino}{cantidad_legitima}{moneda}{timestamp}{nonce}"
firma_valida = hmac.new(mac_key, msg.encode('utf-8'), hashlib.sha256).hexdigest()

# El ataque: Cambiamos la cantidad a 99999€ pero enviamos la firma original
print("\n2. Simulando interceptación MitM (Cambiando cantidad a 99999 sin cambiar MAC)...")
payload_alterado = {
    "session_token": session_data["session_token"],
    "tx_id": tx_id,
    "origin_account": origen,
    "destination_account": destino,
    "amount": 99999.0,
    "currency": moneda,
    "timestamp": timestamp,
    "nonce": nonce,
    "mac": firma_valida 
}

res = requests.post(f"{BASE_URL}/transfer", json=payload_alterado)

print(f"\nResultado del servidor:")
print(f"Código HTTP: {res.status_code}")
print(f"Respuesta: {res.json()}")