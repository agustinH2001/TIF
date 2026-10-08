"""Extracción de CSI desde capturas de Nexmon.

Cada trama CSI es un paquete UDP al puerto 5500 con MAC de origen 4e:45:58:4d:4f:4e;
después de una cabecera de 18 bytes vienen los pares I/Q (int16) de cada subportadora.
"""

import logging
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
from scapy.all import rdpcap, Ether, UDP, Raw
from scapy.error import Scapy_Exception

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("parser_csi")


PUERTO_UDP_NEXMON = 5500

MAC_MAGICA_NEXMON = "4e:45:58:4d:4f:4e"

LONGITUD_CABECERA_NEXMON = 18

DTYPE_IQ = np.dtype("<i2")


def _resolver_ruta_pcap(pcap_path: Optional[str] = None) -> Path:
    """Devuelve la ruta del .pcap a usar (por defecto, data/raw/csi_test.pcap)."""
    raiz_proyecto = Path(__file__).resolve().parents[2]

    if pcap_path is None:
        return raiz_proyecto / "data" / "raw" / "csi_test.pcap"

    ruta = Path(pcap_path)
    if ruta.is_absolute():
        return ruta

    candidato_cwd = Path.cwd() / ruta
    if candidato_cwd.exists():
        return candidato_cwd

    return raiz_proyecto / ruta


def _extraer_payload_csi(paquete) -> Optional[bytes]:
    """Devuelve los bytes I/Q si el paquete es una trama CSI de Nexmon, o None."""
    if not (paquete.haslayer(Ether) and paquete.haslayer(UDP)):
        return None

    if int(paquete[UDP].dport) != PUERTO_UDP_NEXMON:
        return None

    if paquete[Ether].src.lower() != MAC_MAGICA_NEXMON:
        return None

    if not paquete.haslayer(Raw):
        return None

    payload_udp = bytes(paquete[Raw].load)

    if len(payload_udp) <= LONGITUD_CABECERA_NEXMON:
        return None

    return payload_udp[LONGITUD_CABECERA_NEXMON:]


def _calcular_amplitud_fase(datos_iq: bytes) -> Tuple[np.ndarray, np.ndarray]:
    """Convierte los pares I/Q en amplitud y fase por subportadora."""
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
    """Apila los vectores de amplitud descartando los de longitud distinta a la mayoritaria."""
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


def extraer_csi(pcap_path: Optional[str] = None) -> np.ndarray:
    """Lee un .pcap y devuelve la matriz de amplitudes (paquetes x subportadoras)."""
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
        logger.error(f"Error inesperado al leer '{ruta}': {e}")
        return np.empty((0, 0))

    if len(paquetes) == 0:
        logger.warning(f"El archivo .pcap no contiene paquetes: {ruta}")
        return np.empty((0, 0))

    amplitudes_por_paquete: List[np.ndarray] = []

    for paquete in paquetes:
        datos_iq = _extraer_payload_csi(paquete)
        if datos_iq is None:
            continue

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


def inspeccionar_payload_hex(pcap_path: Optional[str] = None, n_paquetes: int = 1) -> None:
    """Imprime en hexadecimal los primeros paquetes CSI (diagnóstico)."""
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


if __name__ == "__main__":
    ruta_prueba = _resolver_ruta_pcap()
    print(f"Buscando archivo de prueba en: {ruta_prueba}")

    matriz_amplitud = extraer_csi(str(ruta_prueba))

    if matriz_amplitud.size == 0:
        print("No se pudo extraer ninguna matriz de amplitud CSI válida.")
    else:
        print(f"Matriz de amplitud CSI extraída con forma: {matriz_amplitud.shape}")
        print(f"  -> {matriz_amplitud.shape[0]} paquetes (muestras temporales)")
        print(f"  -> {matriz_amplitud.shape[1]} subportadoras OFDM")
