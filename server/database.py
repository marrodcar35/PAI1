import sqlite3
from crypto import hash_password

DB_FILE = 'secbank.db'
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME_SECONDS = 10

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Crea las tablas necesarias e inserta usuarios de prueba."""
    conn = get_db_connection()
    cursor = conn.cursor()

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until INTEGER DEFAULT 0
        )
    ''')

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
    ''')

    cursor.execute('SELECT * FROM users WHERE username = ?', ('usuario1',))
    if cursor.fetchone() is None:
        print("Creando usuario de prueba: 'usuario1' con contraseña 'Usuario1@'")
        key, salt = hash_password('Usuario1@')
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
            ('usuario1', key, salt)
        )
        conn.commit()
    else:
        print("La base de datos ya está inicializada.")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            mac_key TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.close()


if __name__ == '__main__':
    init_db()