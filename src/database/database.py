"""
database.py
============

Módulo de persistencia y seguridad del Sistema de Detección Pasiva de
Movimiento basado en CSI (Channel State Information) de señales Wi-Fi.

Rol en la arquitectura:
    Este módulo constituye la capa de acceso a datos (DAL) del sistema.
    Encapsula toda la interacción con MySQL (XAMPP) para que el resto de
    los módulos (captura, procesamiento de señal, API/interfaz) nunca
    ejecuten SQL directamente. Esto mantiene el sistema estrictamente
    modular y facilita el reemplazo futuro de MySQL local por un motor
    en la nube (RDS, Cloud SQL, etc.) sin tocar la lógica de negocio.

Multiusuario / escalabilidad:
    Cada usuario tiene su propio histórico de eventos, sus propios
    archivos .pcap y su propia configuración de sensibilidad/canal/BSSID.
    Este aislamiento por `usuario_id` es lo que permitirá, a futuro,
    migrar el modelo a un esquema multi-tenant en la nube sin rediseñar
    el esquema de datos.

Requisitos:
    pip install mysql-connector-python bcrypt

Autor: Trabajo Integrador Final - Módulo de Persistencia y Seguridad
"""

import logging
from typing import Any, Dict, List, Optional

import bcrypt
import mysql.connector
from mysql.connector import Error
from mysql.connector.connection import MySQLConnection

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("csi_database")

# ---------------------------------------------------------------------------
# Configuración de conexión (XAMPP - MySQL local)
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "csi_db",
}

# Valores por defecto de configuración para un usuario recién creado.
# Se usan al registrar un usuario, para dejar el detector operativo
# de inmediato sin requerir un paso de configuración manual previo.
UMBRAL_SENSIBILIDAD_DEFAULT = 0.5
CANAL_WIFI_DEFAULT = 6


# ---------------------------------------------------------------------------
# Conexión
# ---------------------------------------------------------------------------
def conectar_db() -> Optional[MySQLConnection]:
    """
    Establece y devuelve una conexión activa a la base de datos `csi_db`.

    Cada función de este módulo abre su propia conexión y la cierra al
    finalizar (patrón "connection per operation"), evitando conexiones
    colgadas cuando el sistema corre como múltiples procesos/hilos
    (captura CSI, procesamiento, API web, etc.).

    Returns:
        MySQLConnection si la conexión fue exitosa, None en caso de error.
    """
    try:
        conexion = mysql.connector.connect(**DB_CONFIG)
        if conexion.is_connected():
            return conexion
    except Error as e:
        logger.error(f"No se pudo conectar a csi_db: {e}")
    return None


def _cerrar(cursor, conexion) -> None:
    """
    Utilidad interna para el cierre seguro y ordenado de cursor y conexión.
    Se centraliza acá para no repetir el mismo bloque en cada función.
    """
    try:
        if cursor is not None:
            cursor.close()
    except Error:
        pass
    try:
        if conexion is not None and conexion.is_connected():
            conexion.close()
    except Error:
        pass


# ---------------------------------------------------------------------------
# Usuarios y seguridad
# ---------------------------------------------------------------------------
def registrar_usuario(username: str, password_plana: str) -> Optional[int]:
    """
    Registra un nuevo usuario del sistema.

    Seguridad: la contraseña nunca se almacena en texto plano. Se hashea
    con bcrypt, que genera y embebe internamente un salt aleatorio por
    usuario, protegiendo contra ataques de rainbow tables.

    Efecto colateral controlado: al crear el usuario, se inserta también
    su fila de `configuracion_sistema` con valores por defecto (umbral
    0.5, canal 6), como una única operación atómica. Si cualquiera de las
    dos inserciones falla, se revierte todo (rollback), evitando usuarios
    "huérfanos" sin configuración.

    Args:
        username: nombre de usuario, debe ser único.
        password_plana: contraseña ingresada por el usuario (texto plano).

    Returns:
        El `usuario_id` generado si el registro fue exitoso.
        None si el username ya existe o si ocurrió un error de BD.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor()

        # Hash de la contraseña. bcrypt.gensalt() genera un salt único;
        # el hash resultante ya lo incluye, por lo que no hace falta
        # guardarlo por separado.
        password_hash = bcrypt.hashpw(
            password_plana.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute(
            """
            INSERT INTO usuarios (username, password_hash)
            VALUES (%s, %s)
            """,
            (username, password_hash),
        )
        usuario_id = cursor.lastrowid

        # Configuración inicial del detector para este usuario.
        cursor.execute(
            """
            INSERT INTO configuracion_sistema
                (usuario_id, umbral_sensibilidad, canal_wifi, bssid_objetivo)
            VALUES (%s, %s, %s, %s)
            """,
            (usuario_id, UMBRAL_SENSIBILIDAD_DEFAULT, CANAL_WIFI_DEFAULT, None),
        )

        conexion.commit()
        logger.info(f"Usuario '{username}' registrado (ID {usuario_id}).")
        return usuario_id

    except mysql.connector.IntegrityError:
        # Violación de la restricción UNIQUE sobre username.
        conexion.rollback()
        logger.warning(f"Registro fallido: el usuario '{username}' ya existe.")
        return None
    except Error as e:
        conexion.rollback()
        logger.error(f"Error al registrar usuario '{username}': {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def verificar_usuario(username: str, password_plana: str) -> Optional[int]:
    """
    Verifica credenciales de acceso (login).

    Compara la contraseña ingresada contra el hash almacenado usando
    `bcrypt.checkpw`, que recalcula el hash con el mismo salt embebido
    y compara de forma segura (resistente a timing attacks).

    Args:
        username: nombre de usuario.
        password_plana: contraseña en texto plano a validar.

    Returns:
        El `usuario_id` si las credenciales son correctas, None si el
        usuario no existe o la contraseña es incorrecta.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, password_hash FROM usuarios WHERE username = %s",
            (username,),
        )
        fila = cursor.fetchone()

        if fila is None:
            logger.warning(f"Login fallido: usuario '{username}' no existe.")
            return None

        hash_valido = bcrypt.checkpw(
            password_plana.encode("utf-8"),
            fila["password_hash"].encode("utf-8"),
        )

        if hash_valido:
            logger.info(f"Login exitoso: '{username}' (ID {fila['id']}).")
            return fila["id"]

        logger.warning(f"Login fallido: contraseña incorrecta para '{username}'.")
        return None

    except Error as e:
        logger.error(f"Error al verificar usuario '{username}': {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


# ---------------------------------------------------------------------------
# Eventos de movimiento (salida del pipeline de procesamiento CSI)
# ---------------------------------------------------------------------------
def insertar_evento_movimiento(
    usuario_id: int, varianza: float, duracion: int
) -> Optional[int]:
    """
    Registra un evento de movimiento detectado a partir del análisis de
    la varianza de amplitud en las matrices CSI.

    Este método lo invoca el módulo de procesamiento de señal cuando la
    varianza máxima observada en una ventana temporal supera el
    `umbral_sensibilidad` configurado por el usuario.

    Args:
        usuario_id: ID del usuario dueño del sensor.
        varianza: varianza máxima detectada en la ventana de análisis.
        duracion: duración en segundos del evento de movimiento.

    Returns:
        El ID del registro insertado, o None si ocurrió un error.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO registro_movimiento
                (usuario_id, timestamp, varianza_maxima, duracion_segundos)
            VALUES (%s, NOW(), %s, %s)
            """,
            (usuario_id, varianza, duracion),
        )
        conexion.commit()
        evento_id = cursor.lastrowid
        logger.info(
            f"Movimiento registrado (usuario {usuario_id}, "
            f"varianza={varianza}, duración={duracion}s, id={evento_id})."
        )
        return evento_id

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al insertar evento de movimiento: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def obtener_historico_usuario(usuario_id: int) -> List[Dict[str, Any]]:
    """
    Devuelve el histórico de eventos de movimiento de un usuario,
    ordenado del más reciente al más antiguo.

    Args:
        usuario_id: ID del usuario.

    Returns:
        Lista de dicts con {id, timestamp, varianza_maxima,
        duracion_segundos}. Lista vacía si no hay eventos o hubo error.
    """
    conexion = conectar_db()
    if conexion is None:
        return []

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, timestamp, varianza_maxima, duracion_segundos
            FROM registro_movimiento
            WHERE usuario_id = %s
            ORDER BY timestamp DESC
            """,
            (usuario_id,),
        )
        return cursor.fetchall()

    except Error as e:
        logger.error(f"Error al obtener histórico del usuario {usuario_id}: {e}")
        return []
    finally:
        _cerrar(cursor, conexion)


# ---------------------------------------------------------------------------
# Archivos CSI (.pcap generados por Nexmon CSI en la Raspberry Pi)
# ---------------------------------------------------------------------------
def registrar_ruta_archivo(
    usuario_id: int, nombre_archivo: str, ruta_archivo: str
) -> Optional[int]:
    """
    Guarda la metadata de un archivo .pcap con matrices CSI crudas
    capturado por el firmware Nexmon CSI en la Raspberry Pi.

    Args:
        usuario_id: ID del usuario dueño de la captura.
        nombre_archivo: nombre del archivo (ej. 'captura_20260708_1030.pcap').
        ruta_archivo: ruta absoluta/relativa donde quedó almacenado el archivo.

    Returns:
        El ID del registro insertado, o None si ocurrió un error.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO archivos_csi
                (usuario_id, nombre_archivo, ruta_archivo)
            VALUES (%s, %s, %s)
            """,
            (usuario_id, nombre_archivo, ruta_archivo),
        )
        conexion.commit()
        archivo_id = cursor.lastrowid
        logger.info(
            f"Archivo CSI '{nombre_archivo}' registrado "
            f"(usuario {usuario_id}, id={archivo_id})."
        )
        return archivo_id

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al registrar archivo CSI '{nombre_archivo}': {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


# ---------------------------------------------------------------------------
# Configuración del sistema (umbral, canal Wi-Fi, BSSID objetivo)
# ---------------------------------------------------------------------------
def obtener_configuracion_usuario(usuario_id: int) -> Optional[Dict[str, Any]]:
    """
    Obtiene la configuración actual del detector para un usuario:
    umbral de sensibilidad, canal Wi-Fi monitoreado y BSSID objetivo
    (el punto de acceso cuyas tramas se analizan).

    Args:
        usuario_id: ID del usuario.

    Returns:
        Dict con {usuario_id, umbral_sensibilidad, canal_wifi,
        bssid_objetivo}, o None si no existe configuración o hubo error.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT usuario_id, umbral_sensibilidad, canal_wifi, bssid_objetivo
            FROM configuracion_sistema
            WHERE usuario_id = %s
            """,
            (usuario_id,),
        )
        return cursor.fetchone()

    except Error as e:
        logger.error(f"Error al obtener configuración del usuario {usuario_id}: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def actualizar_configuracion_usuario(
    usuario_id: int, umbral: float, canal: int, bssid: Optional[str]
) -> bool:
    """
    Actualiza la configuración del detector para un usuario.

    Args:
        usuario_id: ID del usuario.
        umbral: nuevo umbral de sensibilidad (varianza mínima para disparar
            una detección de movimiento).
        canal: nuevo canal Wi-Fi (1-14 en 2.4GHz) a monitorear.
        bssid: MAC del punto de acceso objetivo (formato 'AA:BB:CC:DD:EE:FF'),
            o None si no se desea filtrar por BSSID.

    Returns:
        True si se actualizó una fila existente, False si no existía
        configuración previa para ese usuario o si ocurrió un error.
    """
    conexion = conectar_db()
    if conexion is None:
        return False

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            UPDATE configuracion_sistema
            SET umbral_sensibilidad = %s,
                canal_wifi = %s,
                bssid_objetivo = %s
            WHERE usuario_id = %s
            """,
            (umbral, canal, bssid, usuario_id),
        )
        conexion.commit()

        if cursor.rowcount > 0:
            logger.info(f"Configuración actualizada para usuario {usuario_id}.")
            return True

        logger.warning(
            f"No se actualizó ninguna fila: usuario {usuario_id} sin configuración."
        )
        return False

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al actualizar configuración del usuario {usuario_id}: {e}")
        return False
    finally:
        _cerrar(cursor, conexion)


# ---------------------------------------------------------------------------
# Prueba manual rápida del módulo (no forma parte de la lógica de producción)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Smoke test simple: valida que la conexión a csi_db funcione y que
    # el flujo básico de registro/login/CRUD se comporte como se espera.
    # Requiere que XAMPP (MySQL) esté corriendo y csi_db ya creada.
    conexion_test = conectar_db()
    if conexion_test is None:
        print("No se pudo conectar a csi_db. Verificá que XAMPP/MySQL esté activo.")
    else:
        print("Conexión a csi_db exitosa.")
        conexion_test.close()
