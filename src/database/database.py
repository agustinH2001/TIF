"""Acceso a la base de datos MySQL (usuarios, configuración y eventos de movimiento)."""

import logging
from datetime import date, datetime
from typing import Any, Dict, List, Optional

import bcrypt
import mysql.connector
from mysql.connector import Error
from mysql.connector.connection import MySQLConnection
from mysql.connector.constants import ClientFlag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("csi_database")

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "csi_db",
    # rowcount cuenta filas encontradas, no sólo modificadas
    "client_flags": [ClientFlag.FOUND_ROWS],
}

UMBRAL_SENSIBILIDAD_DEFAULT = 0.5


def conectar_db() -> Optional[MySQLConnection]:
    """Abre una conexión a csi_db. Devuelve None si falla."""
    try:
        conexion = mysql.connector.connect(**DB_CONFIG)
        if conexion.is_connected():
            return conexion
    except Error as e:
        logger.error(f"No se pudo conectar a csi_db: {e}")
    return None


def _cerrar(cursor, conexion) -> None:
    """Cierra cursor y conexión ignorando errores."""
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


def registrar_usuario(username: str, password_plana: str) -> Optional[int]:
    """Crea un usuario (contraseña con bcrypt) y su configuración por defecto. Devuelve el id o
    None.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor()

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

        cursor.execute(
            """
            INSERT INTO configuracion_sistema
                (usuario_id, umbral_sensibilidad)
            VALUES (%s, %s)
            """,
            (usuario_id, UMBRAL_SENSIBILIDAD_DEFAULT),
        )

        conexion.commit()
        logger.info(f"Usuario '{username}' registrado (ID {usuario_id}).")
        return usuario_id

    except mysql.connector.IntegrityError:
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
    """Valida las credenciales. Devuelve el id del usuario o None."""
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


def insertar_evento_movimiento(
    usuario_id: int,
    varianza: float,
    duracion: Optional[float] = None,
    timestamp_inicio: Optional[datetime] = None,
) -> Optional[int]:
    """Registra el inicio de un evento de movimiento (timestamp_fin queda NULL). Devuelve el id
    o None.
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
    """Completa un evento con su hora de fin, duración y varianza máxima."""
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
    """Cierra eventos que quedaron sin fin por un corte del programa. Devuelve cuántos cerró."""
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
    """Devuelve el evento más reciente del usuario, o None."""
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
    """Arma la condición SQL para filtrar por rango de días (inclusive)."""
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
    """Devuelve los eventos del usuario, del más reciente al más antiguo, con paginación y
    filtro de fechas opcionales.
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
    """Cantidad de eventos del usuario en el rango de fechas."""
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


def obtener_estadisticas_periodo(
    usuario_id: int, desde: Optional[date] = None, hasta: Optional[date] = None
) -> Dict[str, Any]:
    """Cantidad de eventos, duración total y promedio, e intensidad pico en el rango de fechas."""
    vacio = {"cantidad": 0, "duracion_total": 0.0, "duracion_promedio": 0.0, "varianza_pico": None}
    conexion = conectar_db()
    if conexion is None:
        return vacio

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        sql_fechas, parametros_fechas = _filtro_fechas(desde, hasta)
        cursor.execute(
            "SELECT COUNT(*) AS cantidad, "
            "COALESCE(SUM(duracion_segundos), 0) AS duracion_total, "
            "COALESCE(AVG(duracion_segundos), 0) AS duracion_promedio, "
            "MAX(varianza_maxima) AS varianza_pico "
            "FROM registro_movimiento WHERE usuario_id = %s" + sql_fechas,
            (usuario_id, *parametros_fechas),
        )
        fila = cursor.fetchone() or vacio
        return {
            "cantidad": int(fila["cantidad"]),
            "duracion_total": float(fila["duracion_total"]),
            "duracion_promedio": float(fila["duracion_promedio"]),
            "varianza_pico": None if fila["varianza_pico"] is None else float(fila["varianza_pico"]),
        }

    except Error as e:
        logger.error(f"Error al obtener estadísticas del usuario {usuario_id}: {e}")
        return vacio
    finally:
        _cerrar(cursor, conexion)


def obtener_resumen_diario(usuario_id: int, dias: int = 30) -> List[Dict[str, Any]]:
    """Cantidad de eventos, duración total y varianza pico por día, de los últimos `dias`
    días.
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


def registrar_ruta_archivo(
    usuario_id: int, nombre_archivo: str, ruta_archivo: str
) -> Optional[int]:
    """Registra un archivo de captura CSI. Devuelve el id o None."""
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


SQL_TABLA_SENSOR_ACTIVO = (
    "CREATE TABLE sensor_activo (id TINYINT NOT NULL PRIMARY KEY DEFAULT 1, usuario_id INT NULL, "
    "actualizado TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, "
    "FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL);"
)


class TablaSensorInexistente(RuntimeError):
    """Falta la tabla sensor_activo en la base."""


def _error_tabla_sensor(e: Error) -> None:
    if getattr(e, "errno", None) == 1146:  # ER_NO_SUCH_TABLE
        raise TablaSensorInexistente(
            f"Falta la tabla sensor_activo. Creala en phpMyAdmin con: {SQL_TABLA_SENSOR_ACTIVO}"
        ) from e


def establecer_usuario_activo(usuario_id: int) -> bool:
    """Indica para qué usuario tiene que registrar el sensor (lo llama el Dashboard al iniciar sesión)."""
    conexion = conectar_db()
    if conexion is None:
        return False

    cursor = None
    try:
        cursor = conexion.cursor()
        cursor.execute(
            """
            INSERT INTO sensor_activo (id, usuario_id) VALUES (1, %s)
            ON DUPLICATE KEY UPDATE usuario_id = VALUES(usuario_id)
            """,
            (usuario_id,),
        )
        conexion.commit()
        return True

    except Error as e:
        conexion.rollback()
        if getattr(e, "errno", None) == 1146:
            logger.error(f"Falta la tabla sensor_activo. Creala con: {SQL_TABLA_SENSOR_ACTIVO}")
        else:
            logger.error(f"Error al establecer el usuario activo del sensor: {e}")
        return False
    finally:
        _cerrar(cursor, conexion)


def obtener_usuario_activo() -> Optional[Dict[str, Any]]:
    """Devuelve {usuario_id, username} del usuario activo del sensor, o None si no hay.

    Lanza TablaSensorInexistente si la tabla no fue creada.
    """
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT s.usuario_id, u.username
            FROM sensor_activo s JOIN usuarios u ON u.id = s.usuario_id
            WHERE s.id = 1
            """
        )
        return cursor.fetchone()

    except Error as e:
        _error_tabla_sensor(e)
        logger.error(f"Error al obtener el usuario activo del sensor: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def obtener_configuracion_usuario(usuario_id: int) -> Optional[Dict[str, Any]]:
    """Devuelve {usuario_id, umbral_sensibilidad, guardar_eventos, enviar_alertas} o None."""
    conexion = conectar_db()
    if conexion is None:
        return None

    cursor = None
    try:
        cursor = conexion.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT usuario_id, umbral_sensibilidad, guardar_eventos, enviar_alertas
            FROM configuracion_sistema
            WHERE usuario_id = %s
            """,
            (usuario_id,),
        )
        config = cursor.fetchone()
        if config is not None:
            config["guardar_eventos"] = bool(config["guardar_eventos"])
            config["enviar_alertas"] = bool(config["enviar_alertas"])
        return config

    except Error as e:
        if getattr(e, "errno", None) == 1054:
            logger.error(
                f"Falta una columna en configuracion_sistema ({e.msg}). Columnas necesarias: "
                "guardar_eventos y enviar_alertas, ambas TINYINT(1) NOT NULL DEFAULT 1."
            )
        else:
            logger.error(f"Error al obtener configuración del usuario {usuario_id}: {e}")
        return None
    finally:
        _cerrar(cursor, conexion)


def actualizar_configuracion_usuario(
    usuario_id: int,
    umbral: float,
    guardar_eventos: Optional[bool] = None,
    enviar_alertas: Optional[bool] = None,
) -> bool:
    """Actualiza el umbral y, si se indican, las opciones de guardar eventos y enviar alertas."""
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
                guardar_eventos = COALESCE(%s, guardar_eventos),
                enviar_alertas = COALESCE(%s, enviar_alertas)
            WHERE usuario_id = %s
            """,
            (
                umbral,
                None if guardar_eventos is None else int(bool(guardar_eventos)),
                None if enviar_alertas is None else int(bool(enviar_alertas)),
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


if __name__ == "__main__":
    conexion_test = conectar_db()
    if conexion_test is None:
        print("No se pudo conectar a csi_db. Verificá que XAMPP/MySQL esté activo.")
    else:
        print("Conexión a csi_db exitosa.")
        conexion_test.close()
