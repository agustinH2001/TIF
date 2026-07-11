"""
main.py
=======

Script ejecutable principal del Sistema de Detección Pasiva de Movimiento
por CSI Wi-Fi. Orquesta el ciclo de vida completo del sistema corriendo
en modo local (Raspberry Pi + XAMPP/MySQL):

    1. Autenticación de usuario                (src.database.database)
    2. Carga de configuración personalizada     (src.database.database)
    3. Inicialización del motor DSP             (src.processing.signal_filter)
    4. Streaming de ventanas CSI -> filtrado -> trigger -> persistencia
                                                 (src.parser.parser_csi +
                                                  src.processing.signal_filter)

Nota de estado del hardware (MVP 1):
    Al momento de escribir este orquestador, la Raspberry Pi con Nexmon
    CSI sólo está capturando un único paquete por limitaciones temporales
    de hardware. Por eso este script usa `extraer_csi()` para tomar la
    firma de amplitud REAL de ese paquete como plantilla base, y genera
    matemáticamente ráfagas sintéticas de paquetes sobre esa plantilla
    para poder validar el pipeline de DSP de punta a punta mientras se
    resuelve la captura continua real. Cuando el hardware esté estable,
    el bloque 4 de este script se reemplaza por una lectura continua de
    ventanas reales (o un socket/cola alimentada por el proceso de
    captura), sin tener que tocar el resto del pipeline.

Ejecución:
    Desde la raíz del proyecto:  python src/main.py
    Como módulo:                 python -m src.main
"""

import logging
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

# ---------------------------------------------------------------------------
# Resolución de rutas / imports
# ---------------------------------------------------------------------------
# Este archivo vive en <raiz_proyecto>/src/main.py, por lo que su
# directorio padre directo YA es la raíz del proyecto. Se agrega a
# sys.path para que los imports absolutos "src.<modulo>" funcionen sin
# importar desde dónde se invoque el script (raíz o dentro de src/).
RAIZ_PROYECTO = Path(__file__).resolve().parent.parent
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

from src.database.database import obtener_configuracion_usuario, verificar_usuario
from src.parser.parser_csi import extraer_csi
from src.processing.signal_filter import DetectorMovimiento, FRECUENCIA_MUESTREO_DEFAULT_HZ

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Constantes de la simulación / configuración del sistema
# ---------------------------------------------------------------------------

# Credenciales de la sesión simulada. En una futura interfaz (CLI, API o
# panel web) esto vendría de un formulario de login real, no hardcodeado.
USERNAME_DEMO = "agustin_test"
PASSWORD_DEMO = "Formosa2026!"

# Archivo .pcap real capturado por el MVP 1 (Raspberry Pi + Nexmon CSI).
RUTA_PCAP_REAL = RAIZ_PROYECTO / "data" / "raw" / "csi_test.pcap"

# Tamaño de cada ventana/bloque de análisis, en cantidad de paquetes CSI.
# Nota: la tasa de muestreo (FRECUENCIA_MUESTREO_DEFAULT_HZ, importada de
# signal_filter) determina cuántos segundos reales representa este bloque;
# con el default de 100 Hz, 200 paquetes equivalen a una ventana de 2s.
TAMANO_BLOQUE = 200

# Parámetros de la perturbación de movimiento simulada (banda de pasos).
FRECUENCIA_MOVIMIENTO_HZ = 1.2
AMPLITUD_MOVIMIENTO = 15.0

# Cantidad de subportadoras a usar como fallback si el .pcap real no
# entrega ningún paquete válido (ver `obtener_firma_csi_real`).
N_SUBPORTADORAS_FALLBACK = 64


# ---------------------------------------------------------------------------
# Paso 1: Autenticación
# ---------------------------------------------------------------------------
def autenticar_usuario() -> Optional[int]:
    """
    Simula el inicio de sesión de un usuario ya registrado en el sistema,
    invocando la misma función de verificación que usaría cualquier
    interfaz real (CLI, API, panel web).

    Returns:
        El usuario_id si la autenticación fue exitosa, None en caso
        contrario (usuario inexistente, contraseña incorrecta, o base de
        datos no disponible).
    """
    logger.info(f"Autenticando usuario '{USERNAME_DEMO}'...")
    usuario_id = verificar_usuario(USERNAME_DEMO, PASSWORD_DEMO)

    if usuario_id is None:
        logger.error(
            f"Autenticación fallida para '{USERNAME_DEMO}'. Verificá que: "
            f"(1) XAMPP/MySQL esté corriendo, (2) el usuario exista en "
            f"csi_db.usuarios (podés crearlo con registrar_usuario())."
        )
        return None

    logger.info(f"Autenticación exitosa. usuario_id={usuario_id}")
    return usuario_id


# ---------------------------------------------------------------------------
# Paso 2: Carga de configuración
# ---------------------------------------------------------------------------
def cargar_configuracion(usuario_id: int) -> Optional[dict]:
    """
    Recupera la configuración personalizada del usuario (umbral de
    sensibilidad, canal Wi-Fi, BSSID objetivo) desde `configuracion_sistema`.

    Args:
        usuario_id: ID del usuario autenticado.

    Returns:
        dict con la configuración, o None si no existe/hubo un error.
    """
    logger.info(f"Cargando configuración del sistema (usuario_id={usuario_id})...")
    config = obtener_configuracion_usuario(usuario_id)

    if config is None:
        logger.error(
            f"No se encontró configuración para usuario_id={usuario_id}. "
            f"Todo usuario creado con registrar_usuario() debería tener una "
            f"fila por defecto en configuracion_sistema."
        )
        return None

    logger.info(
        f"Configuración cargada -> umbral_sensibilidad="
        f"{config['umbral_sensibilidad']}, canal_wifi={config['canal_wifi']}, "
        f"bssid_objetivo={config['bssid_objetivo']}"
    )
    return config


# ---------------------------------------------------------------------------
# Paso 4 (preparación): firma CSI real + generación de ráfagas sintéticas
# ---------------------------------------------------------------------------
def obtener_firma_csi_real() -> np.ndarray:
    """
    Extrae, con el parser real (`extraer_csi`), la matriz de amplitud del
    (por ahora único) paquete CSI disponible en `data/raw/csi_test.pcap`.

    Esta firma se usa como plantilla base para generar sintéticamente
    las ráfagas de prueba del paso 4, en lugar de partir de un vector de
    ceros o de ruido puramente artificial: así la simulación conserva la
    "forma" real de amplitud por subportadora del entorno capturado.

    Returns:
        np.ndarray de forma (1, n_subportadoras) con la firma real, o un
        vector de fallback (DC constante) si el .pcap no tiene paquetes
        CSI válidos.
    """
    logger.info(f"Extrayendo firma CSI real desde '{RUTA_PCAP_REAL.name}'...")
    matriz_real = extraer_csi(str(RUTA_PCAP_REAL))

    if matriz_real.size == 0:
        logger.warning(
            "El .pcap real no entregó paquetes CSI válidos (hardware aún "
            "limitado). Se usa una firma de base genérica para poder "
            "seguir validando la lógica de DSP."
        )
        return np.full((1, N_SUBPORTADORAS_FALLBACK), 100.0)

    logger.info(
        f"Firma real obtenida: {matriz_real.shape[0]} paquete(s) x "
        f"{matriz_real.shape[1]} subportadoras."
    )
    return matriz_real


def generar_bloque_reposo(
    firma_base: np.ndarray, n_paquetes: int, rng: np.random.Generator
) -> np.ndarray:
    """
    Genera un bloque sintético de "reposo": repite la firma de amplitud
    real capturada (una fila) a lo largo de `n_paquetes` y le suma
    únicamente ruido blanco de baja intensidad, sin ninguna componente
    de movimiento. Simula un entorno estático.

    Args:
        firma_base: matriz (>=1, n_subportadoras) con la firma real de
            referencia; se usa su primera fila como plantilla.
        n_paquetes: cantidad de paquetes a generar en el bloque.
        rng: generador de números aleatorios de NumPy.

    Returns:
        np.ndarray de forma (n_paquetes, n_subportadoras).
    """
    plantilla = firma_base[0]
    n_subportadoras = plantilla.shape[0]
    ruido = rng.normal(0, 0.5, size=(n_paquetes, n_subportadoras))
    return plantilla + ruido


def generar_bloque_movimiento(
    firma_base: np.ndarray,
    n_paquetes: int,
    frecuencia_muestreo: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """
    Genera un bloque sintético con una perturbación de movimiento
    humano: sobre la misma firma base + ruido, se superpone una onda
    senoidal de ~1.2 Hz (banda típica de pasos) que emula la variación
    de amplitud inducida por una persona moviéndose en el área cubierta.

    Args:
        firma_base: matriz (>=1, n_subportadoras) con la firma real de
            referencia; se usa su primera fila como plantilla.
        n_paquetes: cantidad de paquetes a generar en el bloque.
        frecuencia_muestreo: tasa de paquetes por segundo (Hz), usada
            para construir el eje temporal de la senoidal.
        rng: generador de números aleatorios de NumPy.

    Returns:
        np.ndarray de forma (n_paquetes, n_subportadoras).
    """
    plantilla = firma_base[0]
    n_subportadoras = plantilla.shape[0]

    t = np.arange(n_paquetes) / frecuencia_muestreo
    señal_movimiento = AMPLITUD_MOVIMIENTO * np.sin(2 * np.pi * FRECUENCIA_MOVIMIENTO_HZ * t)

    ruido = rng.normal(0, 0.5, size=(n_paquetes, n_subportadoras))

    # señal_movimiento[:, np.newaxis] transmite (broadcast) la misma
    # perturbación temporal a todas las subportadoras por igual; en una
    # señal CSI real cada subportadora respondería con una fase/ganancia
    # levemente distinta, pero para validar la lógica de trigger esta
    # aproximación es suficiente.
    return plantilla + ruido + señal_movimiento[:, np.newaxis]


# ---------------------------------------------------------------------------
# Utilidad de reporte en consola
# ---------------------------------------------------------------------------
def _imprimir_resultado(resultado: dict) -> None:
    print(f"  Varianza promedio (filtrada) : {resultado['varianza_promedio']:.4f}")
    print(f"  ¿Movimiento detectado?       : {resultado['movimiento_detectado']}")
    print(f"  ¿Evento nuevo en la BD?      : {resultado['evento_registrado']}")


# ---------------------------------------------------------------------------
# Orquestación principal
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 72)
    print(" SISTEMA DE DETECCIÓN PASIVA DE MOVIMIENTO POR CSI WI-FI")
    print(" Orquestador principal (src/main.py) - modo local XAMPP/MySQL")
    print("=" * 72)

    # --- Paso 1: Autenticación ---------------------------------------
    usuario_id = autenticar_usuario()
    if usuario_id is None:
        sys.exit(1)

    # --- Paso 2: Configuración ----------------------------------------
    config = cargar_configuracion(usuario_id)
    if config is None:
        sys.exit(1)

    print(
        f"\n[Info] canal_wifi={config['canal_wifi']} y "
        f"bssid_objetivo={config['bssid_objetivo']} quedan disponibles "
        f"para el futuro módulo de captura (MVP 1); no son consumidos "
        f"por el motor DSP, que sólo necesita el umbral de sensibilidad."
    )

    # --- Paso 3: Inicialización del motor DSP --------------------------
    detector = DetectorMovimiento(
        usuario_id=usuario_id,
        umbral_sensibilidad=config["umbral_sensibilidad"],
        frecuencia_muestreo=FRECUENCIA_MUESTREO_DEFAULT_HZ,
    )
    logger.info(
        f"DetectorMovimiento inicializado con umbral_sensibilidad="
        f"{config['umbral_sensibilidad']} y fs={FRECUENCIA_MUESTREO_DEFAULT_HZ} Hz."
    )

    # --- Preparación del stream simulado --------------------------------
    firma_real = obtener_firma_csi_real()
    rng = np.random.default_rng(seed=7)

    # --- Paso 4: Streaming de ventanas CSI ------------------------------
    print("\n" + "-" * 72)
    print(f"BLOQUE 1/2: simulando {TAMANO_BLOQUE} paquetes de REPOSO (entorno estático)")
    print("-" * 72)
    bloque_reposo = generar_bloque_reposo(firma_real, TAMANO_BLOQUE, rng)
    resultado_reposo = detector.procesar_ventana(bloque_reposo)
    _imprimir_resultado(resultado_reposo)

    time.sleep(1)  # simula el intervalo real entre ventanas del stream continuo

    print("\n" + "-" * 72)
    print(
        f"BLOQUE 2/2: simulando {TAMANO_BLOQUE} paquetes con MOVIMIENTO "
        f"(perturbación ~{FRECUENCIA_MOVIMIENTO_HZ} Hz)"
    )
    print("-" * 72)
    bloque_movimiento = generar_bloque_movimiento(
        firma_real, TAMANO_BLOQUE, FRECUENCIA_MUESTREO_DEFAULT_HZ, rng
    )
    resultado_movimiento = detector.procesar_ventana(bloque_movimiento)
    _imprimir_resultado(resultado_movimiento)

    # --- Resumen final ----------------------------------------------------
    print("\n" + "=" * 72)
    if resultado_movimiento["evento_registrado"]:
        print(
            "✔ Evento de movimiento persistido en 'registro_movimiento' (csi_db).\n"
            "  Revisá phpMyAdmin para confirmar la fila insertada."
        )
    else:
        print(
            "✘ El evento no se persistió en la base de datos.\n"
            "  Revisá el log de errores más arriba (¿XAMPP/MySQL corriendo? "
            "¿el usuario existe en csi_db?)."
        )
    print("=" * 72)


if __name__ == "__main__":
    main()
