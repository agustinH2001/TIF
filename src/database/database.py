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
from datetime import date, datetime
from typing import Any, Dict, List, Optional

import bcrypt
import mysql.connector
from mysql.connector import Error
from mysql.connector.connection import MySQLConnection
from mysql.connector.constants import ClientFlag

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
    # CLIENT_FOUND_ROWS: por defecto, MySQL informa en `cursor.rowcount`
    # la cantidad de filas MODIFICADAS por un UPDATE, no las ENCONTRADAS.
    # Esto es una trampa clásica: si se hace UPDATE con un valor idéntico
    # al que ya estaba guardado, rowcount da 0 aunque la fila exista y la
    # operación haya sido exitosa. Con este flag, rowcount pasa a contar
    # filas encontradas (coincidentes con el WHERE), que es lo que
    # `actualizar_configuracion_usuario` necesita para distinguir
    # correctamente "usuario sin configuración" de "se guardó el mismo
    # valor que ya estaba".
    "client_flags": [ClientFlag.FOUND_ROWS],
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
    usuario_id: int,
    varianza: float,
    duracion: Optional[float] = None,
    timestamp_inicio: Optional[datetime] = None,
) -> Optional[int]:
    """
    Registra el INICIO de un evento de movimiento confirmado por el
    detector (ver `DetectorMovimiento` en signal_filter.py).

    Ciclo de vida de un evento en `registro_movimiento`:
        1. Al confirmarse el movimiento se inserta la fila con la hora de
           inicio, la varianza máxima observada hasta ese momento y
           `timestamp_fin = NULL` / `duracion_segundos = NULL`: el evento
           queda "en curso" y la interfaz puede alertar de inmediato.
        2. Al terminar el movimiento, `finalizar_evento_movimiento`
           completa la hora de fin, la duración real y la varianza
           máxima de todo el evento.

    Args:
        usuario_id: ID del usuario dueño del sensor.
        varianza: varianza máxima observada hasta la confirmación.
        duracion: duración en segundos, si ya se conoce (normalmente
            None: se completa al finalizar el evento).
        timestamp_inicio: momento de inicio real del movimiento (primera
            ventana sobre el umbral). Si es None se usa NOW() del servidor.

    Returns:
        El ID del registro insertado, o None si ocurrió un error.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor()
        if timestamp_inicio is None:
            cursor.execute(
                """
                INSERT INTO registro_movimiento
                    (usuario_id, timestamp, varianza_maxima, duracion_segundos)
                VALUES (%s, NOW(), %s, %s)
                """,
                (usuario_id, varianza, duracion),
            )
        else:
            cursor.execute(
                """
                INSERT INTO registro_movimiento
                    (usuario_id, timestamp, varianza_maxima, duracion_segundos)
                VALUES (%s, %s, %s, %s)
                """,
                (usuario_id, timestamp_inicio, varianza, duracion),
            )
        conexion.commit()
        evento_id = cursor.lastrowid
        logger.info(
            f"Evento de movimiento #{evento_id} iniciado (usuario {usuario_id}, "
            f"varianza={varianza:.4f})."
        )
        return evento_id

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al insertar evento de movimiento: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def finalizar_evento_movimiento(
    evento_id: int,
    timestamp_fin: datetime,
    duracion: float,
    varianza_maxima: float,
) -> bool:
    """
    Completa un evento "en curso" con su hora de fin, su duración real y
    la varianza máxima observada durante TODO el movimiento.

    Returns:
        True si se actualizó el evento, False si no existe o hubo error.
    """
    conexion = conectar_db()
    if conexion is None:
        return False

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            UPDATE registro_movimiento
            SET timestamp_fin = %s,
                duracion_segundos = %s,
                varianza_maxima = GREATEST(COALESCE(varianza_maxima, 0), %s)
            WHERE id = %s
            """,
            (timestamp_fin, duracion, varianza_maxima, evento_id),
        )
        conexion.commit()
        if cursor.rowcount > 0:
            logger.info(
                f"Evento de movimiento #{evento_id} finalizado: duración={duracion:.1f}s, "
                f"varianza_max={varianza_maxima:.4f}."
            )
            return True
        logger.warning(f"No se encontró el evento #{evento_id} para finalizarlo.")
        return False

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al finalizar el evento #{evento_id}: {e}")
        return False
    finally:
        _cerrar(cursor, conexion)


def cerrar_eventos_abiertos(usuario_id: int) -> int:
    """
    Cierra los eventos que quedaron "en curso" (timestamp_fin NULL)
    porque el proceso se interrumpió a mitad de un movimiento (cierre
    abrupto, corte de luz, etc.). Se invoca al arrancar main.py.

    Como la hora de fin real se perdió, se usa la de inicio (duración 0):
    es preferible un dato conservador y explícito a dejar un evento
    "en curso" para siempre, que la interfaz mostraría como alerta activa.

    Returns:
        Cantidad de eventos cerrados (0 si no había o hubo error).
    """
    conexion = conectar_db()
    if conexion is None:
        return 0

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            UPDATE registro_movimiento
            SET timestamp_fin = timestamp,
                duracion_segundos = COALESCE(duracion_segundos, 0)
            WHERE usuario_id = %s AND timestamp_fin IS NULL
            """,
            (usuario_id,),
        )
        conexion.commit()
        return cursor.rowcount

    except Error as e:
        conexion.rollback()
        logger.error(f"Error al cerrar eventos abiertos del usuario {usuario_id}: {e}")
        return 0
    finally:
        _cerrar(cursor, conexion)


def obtener_ultimo_evento(usuario_id: int) -> Optional[Dict[str, Any]]:
    """
    Devuelve el evento más reciente del usuario, o None si no tiene.

    Es la consulta que usa el panel de Monitoreo cada pocos segundos:
    trae UNA sola fila (LIMIT 1) apoyándose en el índice
    (usuario_id, timestamp), en lugar de traer todo el histórico.

    Returns:
        Dict con {id, timestamp, timestamp_fin, varianza_maxima,
        duracion_segundos}. `timestamp_fin` None => evento en curso.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, timestamp, timestamp_fin, varianza_maxima, duracion_segundos
            FROM registro_movimiento
            WHERE usuario_id = %s
            ORDER BY timestamp DESC, id DESC
            LIMIT 1
            """,
            (usuario_id,),
        )
        return cursor.fetchone()

    except Error as e:
        logger.error(f"Error al obtener el último evento del usuario {usuario_id}: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def _filtro_fechas(desde: Optional[date], hasta: Optional[date]):
    """Arma el fragmento WHERE y los parámetros para filtrar por rango de días (inclusive)."""
    condiciones, parametros = [], []
    if desde is not None:
        condiciones.append("timestamp >= %s")
        parametros.append(datetime.combine(desde, datetime.min.time()))
    if hasta is not None:
        condiciones.append("timestamp < DATE_ADD(%s, INTERVAL 1 DAY)")
        parametros.append(datetime.combine(hasta, datetime.min.time()))
    sql = "".join(f" AND {c}" for c in condiciones)
    return sql, parametros


def obtener_historico_usuario(
    usuario_id: int,
    limite: Optional[int] = None,
    desplazamiento: int = 0,
    desde: Optional[date] = None,
    hasta: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """
    Devuelve el histórico de eventos de movimiento de un usuario,
    ordenado del más reciente al más antiguo, con paginación y filtro
    opcional por rango de días.

    Args:
        usuario_id: ID del usuario.
        limite: cantidad máxima de filas (None = todas).
        desplazamiento: filas a saltear (para paginar).
        desde / hasta: días límite, inclusive (None = sin límite).

    Returns:
        Lista de dicts con {id, timestamp, timestamp_fin, varianza_maxima,
        duracion_segundos}. Lista vacía si no hay eventos o hubo error.
    """
    conexion = conectar_db()
    if conexion is None:
        return []

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        sql_fechas, parametros_fechas = _filtro_fechas(desde, hasta)
        sql = (
            "SELECT id, timestamp, timestamp_fin, varianza_maxima, duracion_segundos "
            "FROM registro_movimiento WHERE usuario_id = %s"
            + sql_fechas
            + " ORDER BY timestamp DESC, id DESC"
        )
        parametros: List[Any] = [usuario_id, *parametros_fechas]
        if limite is not None:
            sql += " LIMIT %s OFFSET %s"
            parametros += [int(limite), int(desplazamiento)]
        cursor.execute(sql, tuple(parametros))
        return cursor.fetchall()

    except Error as e:
        logger.error(f"Error al obtener histórico del usuario {usuario_id}: {e}")
        return []
    finally:
        _cerrar(cursor, conexion)


def contar_eventos_usuario(
    usuario_id: int, desde: Optional[date] = None, hasta: Optional[date] = None
) -> int:
    """Cantidad total de eventos del usuario en el rango (para paginar el historial)."""
    conexion = conectar_db()
    if conexion is None:
        return 0

    cursor = None
    try:
        cursor = conexion.cursor()
        sql_fechas, parametros_fechas = _filtro_fechas(desde, hasta)
        cursor.execute(
            "SELECT COUNT(*) FROM registro_movimiento WHERE usuario_id = %s" + sql_fechas,
            (usuario_id, *parametros_fechas),
        )
        return int(cursor.fetchone()[0])

    except Error as e:
        logger.error(f"Error al contar eventos del usuario {usuario_id}: {e}")
        return 0
    finally:
        _cerrar(cursor, conexion)


def obtener_resumen_diario(usuario_id: int, dias: int = 30) -> List[Dict[str, Any]]:
    """
    Estadísticas por día de los últimos `dias` días (sólo días con eventos):
    cantidad de eventos, duración total y varianza pico.

    Returns:
        Lista de dicts {fecha, cantidad, duracion_total, varianza_pico},
        ordenada de la fecha más antigua a la más reciente.
    """
    conexion = conectar_db()
    if conexion is None:
        return []

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT DATE(timestamp) AS fecha,
                   COUNT(*) AS cantidad,
                   COALESCE(SUM(duracion_segundos), 0) AS duracion_total,
                   MAX(varianza_maxima) AS varianza_pico
            FROM registro_movimiento
            WHERE usuario_id = %s
              AND timestamp >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
            GROUP BY DATE(timestamp)
            ORDER BY fecha ASC
            """,
            (usuario_id, max(int(dias) - 1, 0)),
        )
        return cursor.fetchall()

    except Error as e:
        logger.error(f"Error al obtener el resumen diario del usuario {usuario_id}: {e}")
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
    umbral de sensibilidad, canal Wi-Fi monitoreado, BSSID objetivo
    (el punto de acceso cuyas tramas se analizan) y si los eventos de
    movimiento se guardan en el historial.

    Args:
        usuario_id: ID del usuario.

    Returns:
        Dict con {usuario_id, umbral_sensibilidad, canal_wifi,
        bssid_objetivo, guardar_eventos (bool)}, o None si no existe
        configuración o hubo error.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT usuario_id, umbral_sensibilidad, canal_wifi, bssid_objetivo,
                   guardar_eventos
            FROM configuracion_sistema
            WHERE usuario_id = %s
            """,
            (usuario_id,),
        )
        config = cursor.fetchone()
        if config is not None:
            config["guardar_eventos"] = bool(config["guardar_eventos"])
        return config

    except Error as e:
        if getattr(e, "errno", None) == 1054:  # ER_BAD_FIELD_ERROR: columna inexistente
            logger.error(
                "Falta la columna 'guardar_eventos' en configuracion_sistema. Ejecutá en "
                "phpMyAdmin: ALTER TABLE configuracion_sistema ADD COLUMN guardar_eventos "
                "TINYINT(1) NOT NULL DEFAULT 1;"
            )
        else:
            logger.error(f"Error al obtener configuración del usuario {usuario_id}: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def actualizar_configuracion_usuario(
    usuario_id: int,
    umbral: float,
    canal: int,
    bssid: Optional[str],
    guardar_eventos: Optional[bool] = None,
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
        guardar_eventos: si los eventos de movimiento se guardan en el
            historial. None = no modificar el valor actual.

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
                bssid_objetivo = %s,
                guardar_eventos = COALESCE(%s, guardar_eventos)
            WHERE usuario_id = %s
            """,
            (
                umbral,
                canal,
                bssid,
                None if guardar_eventos is None else int(bool(guardar_eventos)),
                usuario_id,
            ),
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
