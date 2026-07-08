import mysql.connector
from mysql.connector import Error

def conectar_db():
    """Establece la conexión con el servidor MySQL de XAMPP."""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',       # Usuario por defecto de XAMPP
            password='',       # Contraseña por defecto de XAMPP (vacía)
            database='csi_db'
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error al conectar a MySQL: {e}")
        return None

# Ejemplo de cómo registrarías un usuario con contraseña segura desde tu código:
import bcrypt

def registrar_usuario(username, password_plana):
    conn = conectar_db()
    if conn is None: return
    
    cursor = conn.cursor()
    
    # 1. Encriptar la contraseña en el código
    salt = bcrypt.gensalt()
    hash_contrasena = bcrypt.hashpw(password_plana.encode('utf-8'), salt).decode('utf-8')
    
    try:
        # 2. Guardar solo el hash en la base de datos
        query = "INSERT INTO usuarios (username, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (username, hash_contrasena))
        conn.commit()
        print(f"Usuario '{username}' registrado exitosamente.")
    except Error as e:
        print(f"Error al registrar usuario: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    # Prueba de conexión e inserción inicial si el servidor de XAMPP está encendido
    print("Probando conexión con XAMPP...")
    # registrar_usuario("agustin_hermosilla", "Formosa2026")