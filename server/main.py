import time
import os
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware #
from pydantic import BaseModel
import uvicorn

# Importamos nuestras funciones de base de datos y seguridad
from database import get_db_connection, MAX_FAILED_ATTEMPTS, LOCKOUT_TIME_SECONDS
from crypto import *
app = FastAPI(title="SecBank API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción se pone el dominio real, aquí permitimos todo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Definimos la estructura esperada para el Login
class LoginRequest(BaseModel):
    username: str
    password: str

# 1. Definimos la estructura esperada para el Logout
class LogoutRequest(BaseModel):
    session_token: str

class RegisterRequest(BaseModel):
    username: str
    password: str

# 3. Definimos la estructura de la Transacción según el documento
class TransferRequest(BaseModel):
    session_token: str
    tx_id: str
    origin_account: str
    destination_account: str
    amount: float
    currency: str
    timestamp: int
    nonce: str
    mac: str

@app.get("/")
def serve_frontend():
    # Buscamos la ruta de tu index.html que está en la carpeta 'cliente'
    ruta_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_index = os.path.join(ruta_actual, "..", "cliente", "index.html")
    
    return FileResponse(ruta_index)

# 3. Endpoint de Inicio de Sesión
@app.post("/api/v1/login")
def login(request: LoginRequest):
    
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    try:   
        # Buscamos al usuario en la base de datos
        cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
        user = cursor.fetchone()

        # Si el usuario no existe, damos un error genérico por seguridad
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        # --- NUEVO (RS1): Verificar si la cuenta está bloqueada ---
        if user['lockout_until'] > current_time:
            remaining = user['lockout_until'] - current_time
            raise HTTPException(status_code=429, detail=f"Cuenta bloqueada. Reintente en {remaining} segundos.")
        
        # Verificamos la contraseña usando nuestra función segura (Tiempo Constante)
        is_valid = verify_password(user['password_hash'], user['salt'], request.password)
        
        if not is_valid:
            if user['lockout_until'] > 0 and user['lockout_until'] <= current_time:
                new_attempts = 1
            else:
                new_attempts = user['failed_attempts'] + 1
                
            lockout_time = current_time + LOCKOUT_TIME_SECONDS if new_attempts >= MAX_FAILED_ATTEMPTS else 0

            cursor.execute(
                "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
                (new_attempts, lockout_time, user['id'])
            )
            conn.commit()

            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id = ?", (user['id'],))
        
        session_token = generate_mac_key().hex()
        
        # 2. Generamos la clave secreta MAC exclusiva para esta sesión usando crypto.py
        mac_key_hex = generate_mac_key().hex()
        
        # 3. La sesión caduca en 1 hora (3600 segundos)
        expires_at = current_time + 3600

        cursor.execute(
            "INSERT INTO sessions (session_token, user_id, mac_key, expires_at) VALUES (?, ?, ?, ?)",
            (session_token, user['id'], mac_key_hex, expires_at)
        )
        conn.commit()

        return {
            "message": f"Login exitoso",
            "session_token": session_token,
            "mac_key": mac_key_hex,
            "expires_in": 3600
        }


        return {"message": f"Login exitoso para {request.username}"}

    finally:
        conn.close()

@app.post("/api/v1/logout")
def logout(request: LogoutRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Verificamos si la sesión existe
        cursor.execute("SELECT * FROM sessions WHERE session_token = ?", (request.session_token,))
        session = cursor.fetchone()
        
        if not session:
            raise HTTPException(status_code=401, detail="Sesión inválida o ya cerrada")
            
        # Eliminamos la sesión de la base de datos para invalidarla
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (request.session_token,))
        conn.commit()
        
        return {"message": "Sesión cerrada correctamente"}
    finally:
        conn.close()

@app.post("/api/v1/register")
def register(request: RegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 1. Validar la política de contraseñas
        # Mínimo 8 caracteres, 1 letra, 1 número, 1 símbolo
        patron = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>])[A-Za-z\d!@#$%^&*(),.?\":{}|<>]{8,}$"
        
        if not re.match(patron, request.password):
            raise HTTPException(
                status_code=400, 
                detail="La contraseña debe tener al menos 8 caracteres, incluir 1 letra, 1 número y 1 símbolo."
            )

        # 2. Comprobar si el usuario ya existe (Evitar duplicados)
        cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El usuario ya existe. Elige otro nombre.")

        # 3. Derivación robusta (Requisito RS1)
        key, salt = hash_password(request.password)

        # 4. Guardar usuario en la base de datos
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (request.username, key, salt)
        )
        conn.commit()
        
        return {"message": f"Usuario '{request.username}' registrado correctamente"}
    finally:
        conn.close()



    # -----------------------------------------
# ENDPOINT DE TRANSFERENCIA
# -----------------------------------------
@app.post("/api/v1/transfer")
def transfer(request: TransferRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    
    try:
        #  Validar ventana de tiempo (rechazamos peticiones con más de 5 minutos de antigüedad)
        if abs(current_time - request.timestamp) > 300:
            raise HTTPException(status_code=403, detail="Timestamp caducado. Posible ataque Replay.")
            
        #  Validar que el Nonce no haya sido utilizado antes
        cursor.execute("SELECT * FROM nonces WHERE nonce = ?", (request.nonce,))
        if cursor.fetchone():
            raise HTTPException(status_code=403, detail="Nonce ya utilizado. Ataque Replay detectado.")

        # 1. Buscamos la sesión del usuario en la base de datos
        cursor.execute("SELECT * FROM sessions WHERE session_token = ?", (request.session_token,))
        session = cursor.fetchone()
        
        # Si la sesión no existe o ha caducado
        if not session or session['expires_at'] < current_time:
            raise HTTPException(status_code=401, detail="Sesión inválida o caducada")
            
        # 2. Recuperamos la clave MAC secreta que le asignamos en su login
        # Como está en hexadecimal, la pasamos a bytes
        mac_key = bytes.fromhex(session['mac_key'])
        
        # 3. Concatenamos los datos para validarlos
        message = f"{request.tx_id}{request.origin_account}{request.destination_account}{request.amount}{request.currency}{request.timestamp}"
        
        # 4. Verificamos la firma MAC usando LA CLAVE DE SU SESIÓN
        is_valid_mac = verify_hmac_sha256(mac_key, message, request.mac)
        
        if not is_valid_mac:
            raise HTTPException(
                status_code=403, 
                detail="Firma MAC inválida. La transacción ha sido alterada o no es auténtica."
            )
        
        # Aquí iría tu lógica de inserción de transferencia
        
        return {
            "status": "success", 
            "message": "Firma MAC validada correctamente con clave de sesión", 
            "tx_id": request.tx_id
        }
    finally:
        conn.close()

if __name__ == "__main__":
    # Arrancamos el servidor en el puerto 8080 (No seguro, como pide la Opción B)
    uvicorn.run(app, host="127.0.0.1", port=8080)