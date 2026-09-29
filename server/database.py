import sqlite3
import os
from crypto import hash_password

DB_FILE = 'secbank.db'

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row # Permite acceder a las columnas por nombre
    return conn

def init_db():
    """Crea las tablas necesarias e inserta usuarios de prueba."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabla de Usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL
        )
    ''')

    # Tabla de Nonces (Para prevenir ataques de Replay - RS3)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
    ''')

    # Población de datos: Usuario de prueba
    cursor.execute('SELECT * FROM users WHERE username = ?', ('usuario1',))
    if cursor.fetchone() is None:
        print("Creando usuario de prueba: 'usuario1' con contraseña '123456'")
        key, salt = hash_password('123456')
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
            ('usuario1', key, salt)
        )
        conn.commit()
    else:
        print("La base de datos ya está inicializada.")

    conn.close()

# Si ejecutamos este archivo directamente, se inicializará la base de datos
if __name__ == '__main__':
    init_db()