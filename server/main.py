from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Importamos nuestras funciones de base de datos y seguridad
from database import get_db_connection
from crypto import verify_password

app = FastAPI(title="SecBank API")

# 1. Definimos la estructura esperada para el Login
class LoginRequest(BaseModel):
    username: str
    password: str

# 2. Definimos la estructura de la Transacción según el documento
class TransferRequest(BaseModel):
    tx_id: str
    origin_account: str
    destination_account: str
    amount: float
    currency: str
    timestamp: int

# 3. Endpoint de Inicio de Sesión
@app.post("/api/v1/login")
def login(request: LoginRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Buscamos al usuario en la base de datos
    cursor.execute("SELECT * FROM users WHERE username = ?", (request.username,))
    user = cursor.fetchone()
    conn.close()

    # Si el usuario no existe, damos un error genérico por seguridad
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    # Verificamos la contraseña usando nuestra función segura (Tiempo Constante)
    is_valid = verify_password(user['password_hash'], user['salt'], request.password)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    return {"message": f"Login exitoso para {request.username}"}

if __name__ == "__main__":
    # Arrancamos el servidor en el puerto 8080 (No seguro, como pide la Opción B)
    uvicorn.run(app, host="127.0.0.1", port=8080)