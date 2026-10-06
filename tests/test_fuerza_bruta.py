import requests
import time

BASE_URL = "http://127.0.0.1:8080/api/v1"
USERNAME = "usuario1"
WRONG_PASSWORD = "password_incorrecta"
RIGHT_PASSWORD = "Usuario1@"

print("Simulando ataque de fuerza bruta...\n")

# Hacemos 4 intentos fallidos seguidos
for i in range(1, 5):
    print(f"Intento {i} (Contraseña incorrecta)...")
    res = requests.post(f"{BASE_URL}/login", json={"username": USERNAME, "password": WRONG_PASSWORD})
    print(f"Código HTTP: {res.status_code} | Respuesta: {res.json()}")
    time.sleep(1)

print("\nIntentando acceder con la contraseña CORRECTA mientras la cuenta está bloqueada...")
res_bloqueado = requests.post(f"{BASE_URL}/login", json={"username": USERNAME, "password": RIGHT_PASSWORD})
print(f"Código HTTP: {res_bloqueado.status_code} | Respuesta: {res_bloqueado.json()}")

print("\nEsperando 11 segundos para que se levante el bloqueo temporal...")
time.sleep(11)

print("Intentando acceder de nuevo con la contraseña CORRECTA...")
res_ok = requests.post(f"{BASE_URL}/login", json={"username": USERNAME, "password": RIGHT_PASSWORD})
print(f"Código HTTP: {res_ok.status_code} | Respuesta: {res_ok.json()}")