import requests
import time
import hmac
import hashlib
import uuid

BASE_URL = "http://127.0.0.1:8080/api/v1"

print("1. Iniciando sesión legítima...")
login_res = requests.post(f"{BASE_URL}/login", json={"username": "usuario1", "password": "Usuario1@"})
if login_res.status_code != 200:
    print("Error en login. Asegúrate de que el servidor está encendido.")
    exit()

session_data = login_res.json()
mac_key = bytes.fromhex(session_data["mac_key"])

# Preparamos una transferencia perfectamente válida
tx_id = "tx-replay-001"
origen = "ES12345678"
destino = "ES87654321"
cantidad = 150.0
moneda = "EUR"
timestamp = int(time.time())
nonce = str(uuid.uuid4()) # Generamos un Nonce único

# Calculamos la firma MAC
msg = f"{tx_id}{origen}{destino}{cantidad}{moneda}{timestamp}{nonce}"
firma_valida = hmac.new(mac_key, msg.encode('utf-8'), hashlib.sha256).hexdigest()

payload = {
    "session_token": session_data["session_token"],
    "tx_id": tx_id,
    "origin_account": origen,
    "destination_account": destino,
    "amount": cantidad,
    "currency": moneda,
    "timestamp": timestamp,
    "nonce": nonce,
    "mac": firma_valida
}

print("\n2. Envío legítimo (El servidor debe aceptarlo e invalidar el Nonce)...")
res1 = requests.post(f"{BASE_URL}/transfer", json=payload)
print(f"Código HTTP: {res1.status_code} | Respuesta: {res1.json()}")

print("\n3. Simulando Ataque Replay (Reenviando el mismo paquete capturado)...")
res2 = requests.post(f"{BASE_URL}/transfer", json=payload)
print(f"Código HTTP: {res2.status_code} | Respuesta: {res2.json()}")