"""
parser_csi.py
=============

Módulo de parsing y extracción de datos CSI (Channel State Information)
a partir de archivos .pcap generados por el firmware Nexmon CSI en la
Raspberry Pi (MVP 1).

Formato de captura (Nexmon CSI):
    - Las tramas CSI viajan encapsuladas como paquetes UDP con destino al
      puerto 5500.
    - Nexmon "marca" estas tramas usando, en la capa Ethernet simulada,
      la dirección MAC de origen 4e:45:58:4d:4f:4e, que son los bytes
      ASCII de la palabra "NEXMON". Esto permite distinguir tramas CSI
      de cualquier otro tráfico que pudiera haber quedado en la captura.
    - El payload UDP trae, primero, una cabecera interna fija de Nexmon
      (magic bytes, RSSI, MAC de la trama Wi-Fi original, número de
      secuencia, core/stream y chanspec) y, a continuación, los valores
      crudos de CSI: pares consecutivos de enteros int16 con signo,
      little-endian, correspondientes a la componente En-Fase (I) y en
      Cuadratura (Q) de cada subportadora OFDM.

Rol en el pipeline:
    Este módulo es el primer eslabón del MVP 2. Su única responsabilidad
    es transformar el .pcap crudo en una matriz de NumPy de amplitudes
    (paquetes x subportadoras), lista para que el siguiente módulo
    (procesamiento de señal / detección de movimiento) la consuma sin
    tener que conocer nada sobre el formato de Nexmon ni de Scapy.

Requisitos:
    pip install scapy numpy

Autor: Trabajo Integrador Final - Módulo Parser/Extractor CSI
"""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
from scapy.all import rdpcap, Ether, UDP, Raw
from scapy.error import Scapy_Exception

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("parser_csi")

# ---------------------------------------------------------------------------
# Constantes del formato Nexmon CSI
# ---------------------------------------------------------------------------

# Puerto UDP donde Nexmon CSI vuelca las tramas con datos crudos de CSI.
PUERTO_UDP_NEXMON = 5500

# MAC "mágica" que Nexmon CSI utiliza como dirección de origen en la capa
# Ethernet simulada, para poder distinguir tramas CSI del resto del
# tráfico. Corresponde a los bytes ASCII de la palabra "NEXMON"
# (4e 45 58 4d 4f 4e).
MAC_MAGICA_NEXMON = "4e:45:58:4d:4f:4e"

# Longitud (en bytes) de la cabecera interna fija que Nexmon antepone a
# los valores I/Q dentro del payload UDP. Es el valor típicamente citado
# en la documentación y en herramientas de la comunidad Nexmon CSI, pero
# puede variar levemente según la versión de firmware/parche utilizada.
#
# IMPORTANTE: antes de usar esto con capturas reales del equipo, validar
# este número con la función auxiliar `inspeccionar_payload_hex()` de
# este mismo módulo (ver bloque main), comparando la longitud total del
# payload contra la cantidad de subportadoras esperada según el ancho de
# banda configurado (20MHz -> 64, 40MHz -> 128, 80MHz -> 256).
LONGITUD_CABECERA_NEXMON = 18

# Formato de cada valor I/Q: entero de 16 bits con signo, little-endian
# (propio de los chipsets Broadcom/Cypress que soporta Nexmon).
DTYPE_IQ = np.dtype("<i2")


# ---------------------------------------------------------------------------
# Resolución robusta de rutas
# ---------------------------------------------------------------------------
def _resolver_ruta_pcap(pcap_path: Optional[str] = None) -> Path:
    """
    Resuelve la ruta al archivo .pcap sin importar si el script se
    ejecuta desde la raíz del proyecto o desde src/parser/.

    Args:
        pcap_path: ruta (absoluta o relativa) provista por el usuario.
            Si es None, se usa por defecto 'data/raw/csi_test.pcap'
            relativo a la raíz del proyecto.

    Returns:
        Path resuelto al archivo .pcap (puede no existir; la validación
        de existencia se hace en `extraer_csi`).
    """
    # Este archivo vive en <raiz_proyecto>/src/parser/parser_csi.py,
    # por lo que subir 2 niveles desde su ubicación da la raíz del proyecto.
    raiz_proyecto = Path(__file__).resolve().parents[2]

    if pcap_path is None:
        return raiz_proyecto / "data" / "raw" / "csi_test.pcap"

    ruta = Path(pcap_path)
    if ruta.is_absolute():
        return ruta

    # 1) Probar relativo al directorio de trabajo actual (por si se
    #    ejecuta "python parser_csi.py" parado en src/parser/).
    candidato_cwd = Path.cwd() / ruta
    if candidato_cwd.exists():
        return candidato_cwd

    # 2) Si no existe ahí, probar relativo a la raíz del proyecto (por
    #    si se ejecuta desde la raíz, ej. "python -m src.parser.parser_csi").
    return raiz_proyecto / ruta


# ---------------------------------------------------------------------------
# Filtrado y extracción por paquete
# ---------------------------------------------------------------------------
def _extraer_payload_csi(paquete) -> Optional[bytes]:
    """
    Filtra un paquete de Scapy y, si corresponde a una trama CSI de
    Nexmon válida (UDP puerto 5500 + MAC de origen "NEXMON"), devuelve
    los bytes crudos de datos I/Q (payload UDP sin la cabecera interna
    de Nexmon).

    Args:
        paquete: paquete individual devuelto por `scapy.rdpcap`.

    Returns:
        bytes con los datos I/Q crudos, o None si el paquete no cumple
        los criterios de filtrado (no es una trama CSI válida).
    """
    if not (paquete.haslayer(Ether) and paquete.haslayer(UDP)):
        return None

    # Filtro 1: puerto UDP de destino == 5500 (tramas CSI de Nexmon).
    if int(paquete[UDP].dport) != PUERTO_UDP_NEXMON:
        return None

    # Filtro 2: MAC de origen "mágica" que marca las tramas Nexmon CSI.
    if paquete[Ether].src.lower() != MAC_MAGICA_NEXMON:
        return None

    if not paquete.haslayer(Raw):
        return None

    payload_udp = bytes(paquete[Raw].load)

    if len(payload_udp) <= LONGITUD_CABECERA_NEXMON:
        # El payload no tiene datos CSI reales más allá de la cabecera.
        return None

    return payload_udp[LONGITUD_CABECERA_NEXMON:]


def _calcular_amplitud_fase(datos_iq: bytes) -> Tuple[np.ndarray, np.ndarray]:
    """
    Convierte los bytes crudos de un paquete en pares (I, Q) y calcula,
    de forma vectorizada con NumPy, la amplitud y la fase de cada
    subportadora.

    Args:
        datos_iq: bytes con pares I,Q consecutivos (int16 little-endian).

    Returns:
        Tupla (amplitud, fase) como np.ndarray de float64. Ambos vacíos
        si `datos_iq` no alcanza para al menos un par I/Q completo.
    """
    # Cada muestra (I o Q) ocupa 2 bytes; un par (I, Q) ocupa 4 bytes.
    n_pares = len(datos_iq) // 4
    if n_pares == 0:
        return np.array([]), np.array([])

    bytes_utiles = datos_iq[: n_pares * 4]
    muestras = np.frombuffer(bytes_utiles, dtype=DTYPE_IQ)

    I = muestras[0::2].astype(np.float64)
    Q = muestras[1::2].astype(np.float64)

    amplitud = np.sqrt(I**2 + Q**2)
    fase = np.arctan2(Q, I)

    return amplitud, fase


def _apilar_con_longitud_consistente(lista_amplitudes: List[np.ndarray]) -> np.ndarray:
    """
    Apila los vectores de amplitud de cada paquete en una única matriz
    (n_paquetes x n_subportadoras).

    En una captura real puede haber paquetes truncados/corruptos con una
    cantidad de subportadoras distinta a la mayoría. Para no romper el
    armado de la matriz final, se conserva la longitud más frecuente
    (moda) y se descartan los paquetes que no coincidan.

    Args:
        lista_amplitudes: lista de vectores de amplitud (uno por paquete).

    Returns:
        np.ndarray 2D con todos los vectores de amplitud de longitud
        consistente apilados por filas.
    """
    longitudes = [a.shape[0] for a in lista_amplitudes]
    longitud_moda = max(set(longitudes), key=longitudes.count)

    filas_validas = [a for a in lista_amplitudes if a.shape[0] == longitud_moda]
    descartados = len(lista_amplitudes) - len(filas_validas)

    if descartados > 0:
        logger.warning(
            f"Se descartaron {descartados} paquete(s) con una cantidad de "
            f"subportadoras distinta a la esperada ({longitud_moda})."
        )

    return np.vstack(filas_validas)


# ---------------------------------------------------------------------------
# Función principal del módulo
# ---------------------------------------------------------------------------
def extraer_csi(pcap_path: Optional[str] = None) -> np.ndarray:
    """
    Extrae la matriz de amplitudes CSI a partir de un archivo .pcap
    capturado con Nexmon CSI.

    Pipeline de extracción:
        1. Abre el .pcap con Scapy y filtra únicamente los paquetes UDP
           con destino al puerto 5500 y MAC de origen "NEXMON".
        2. De cada paquete válido, descarta la cabecera interna fija de
           Nexmon y extrae los pares (I, Q) como enteros int16 con signo.
        3. Calcula la amplitud de cada subportadora de forma vectorizada:
           A = sqrt(I^2 + Q^2).
        4. Apila las amplitudes de todos los paquetes válidos en una
           matriz (n_paquetes x n_subportadoras).

    Args:
        pcap_path: ruta al archivo .pcap. Si es None, se usa por defecto
            'data/raw/csi_test.pcap' relativo a la raíz del proyecto.

    Returns:
        np.ndarray de forma (n_paquetes, n_subportadoras) con las
        amplitudes CSI (float64), listo para el siguiente módulo del
        pipeline. Devuelve un array vacío de forma (0, 0) si el archivo
        no existe, está vacío, está corrupto, o no contiene ningún
        paquete CSI válido.
    """
    ruta = _resolver_ruta_pcap(pcap_path)

    if not ruta.exists():
        logger.error(f"El archivo .pcap no existe: {ruta}")
        return np.empty((0, 0))

    if ruta.stat().st_size == 0:
        logger.error(f"El archivo .pcap está vacío (0 bytes): {ruta}")
        return np.empty((0, 0))

    try:
        paquetes = rdpcap(str(ruta))
    except Scapy_Exception as e:
        logger.error(f"Error al leer el archivo .pcap '{ruta}': {e}")
        return np.empty((0, 0))
    except Exception as e:
        # Cubre errores de bajo nivel (archivo corrupto, formato inválido, etc.)
        logger.error(f"Error inesperado al leer '{ruta}': {e}")
        return np.empty((0, 0))

    if len(paquetes) == 0:
        logger.warning(f"El archivo .pcap no contiene paquetes: {ruta}")
        return np.empty((0, 0))

    amplitudes_por_paquete: List[np.ndarray] = []

    for paquete in paquetes:
        datos_iq = _extraer_payload_csi(paquete)
        if datos_iq is None:
            continue  # paquete descartado: no es una trama CSI válida

        amplitud, _fase = _calcular_amplitud_fase(datos_iq)
        if amplitud.size > 0:
            amplitudes_por_paquete.append(amplitud)

    if not amplitudes_por_paquete:
        logger.warning(
            f"No se encontraron paquetes CSI válidos (UDP puerto "
            f"{PUERTO_UDP_NEXMON}, MAC origen {MAC_MAGICA_NEXMON}) en '{ruta}'."
        )
        return np.empty((0, 0))

    matriz_amplitud = _apilar_con_longitud_consistente(amplitudes_por_paquete)

    logger.info(
        f"CSI extraído de '{ruta.name}': {matriz_amplitud.shape[0]} paquetes "
        f"x {matriz_amplitud.shape[1]} subportadoras."
    )
    return matriz_amplitud


# ---------------------------------------------------------------------------
# Utilidad de diagnóstico (no forma parte del pipeline de producción)
# ---------------------------------------------------------------------------
def inspeccionar_payload_hex(pcap_path: Optional[str] = None, n_paquetes: int = 1) -> None:
    """
    Imprime en hexadecimal el payload UDP crudo de los primeros paquetes
    CSI encontrados en el .pcap. Es una herramienta de diagnóstico para
    validar/ajustar manualmente `LONGITUD_CABECERA_NEXMON` contra una
    captura real (por ejemplo, ubicando visualmente dónde terminan los
    campos de cabecera y empiezan los pares I/Q).

    Args:
        pcap_path: ruta al .pcap a inspeccionar (ver `extraer_csi`).
        n_paquetes: cantidad de paquetes CSI a mostrar.
    """
    ruta = _resolver_ruta_pcap(pcap_path)
    if not ruta.exists():
        print(f"El archivo .pcap no existe: {ruta}")
        return

    paquetes = rdpcap(str(ruta))
    mostrados = 0

    for paquete in paquetes:
        if not (paquete.haslayer(Ether) and paquete.haslayer(UDP) and paquete.haslayer(Raw)):
            continue
        if int(paquete[UDP].dport) != PUERTO_UDP_NEXMON:
            continue
        if paquete[Ether].src.lower() != MAC_MAGICA_NEXMON:
            continue

        payload = bytes(paquete[Raw].load)
        print(f"\nPaquete CSI #{mostrados + 1} - {len(payload)} bytes de payload:")
        print(f"  Cabecera (primeros {LONGITUD_CABECERA_NEXMON} bytes): "
              f"{payload[:LONGITUD_CABECERA_NEXMON].hex(' ')}")
        print(f"  Datos I/Q (resto): {payload[LONGITUD_CABECERA_NEXMON:LONGITUD_CABECERA_NEXMON + 32].hex(' ')} ...")

        mostrados += 1
        if mostrados >= n_paquetes:
            break

    if mostrados == 0:
        print("No se encontraron paquetes CSI válidos para inspeccionar.")


# ---------------------------------------------------------------------------
# Prueba manual del módulo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ruta_prueba = _resolver_ruta_pcap()  # data/raw/csi_test.pcap por defecto
    print(f"Buscando archivo de prueba en: {ruta_prueba}")

    matriz_amplitud = extraer_csi(str(ruta_prueba))

    if matriz_amplitud.size == 0:
        print("No se pudo extraer ninguna matriz de amplitud CSI válida.")
    else:
        print(f"Matriz de amplitud CSI extraída con forma: {matriz_amplitud.shape}")
        print(f"  -> {matriz_amplitud.shape[0]} paquetes (muestras temporales)")
        print(f"  -> {matriz_amplitud.shape[1]} subportadoras OFDM")
