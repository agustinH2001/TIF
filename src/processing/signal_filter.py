"""
signal_filter.py
=================

Motor lógico de detección de movimiento del MVP 2.

Este módulo toma la matriz de amplitudes CSI producida por
`src.parser.parser_csi` (forma: n_paquetes x n_subportadoras) y ejecuta
el pipeline de procesamiento de señal que decide si hubo movimiento:

    1. Filtrado digital (Butterworth pasabanda, forma SOS) subportadora
       por subportadora, para quedarse únicamente con la banda de
       frecuencia típica del movimiento humano.
    2. Cálculo de la varianza promedio de la señal filtrada: la métrica
       de "agitación del canal".
    3. Evaluación de un trigger por umbral sobre esa métrica — SÓLO si
       la ventana pudo filtrarse. Una ventana sin filtrar no es
       comparable contra el umbral (ver "Ventanas inválidas" abajo).
    4. Persistencia del evento en la base de datos, únicamente en el
       flanco ascendente de la detección (False -> True), para no
       duplicar el mismo evento de movimiento en cada ventana analizada.

Ventanas inválidas (instrumentación del fallback):
    En pruebas en vivo con tráfico generado por `ping` (fs real de 2 a
    15 Hz), el filtro no se podía aplicar y la ventana caía en el
    fallback "señal sin filtrar". La varianza de la señal CRUDA incluye
    la deriva lenta del canal y el ruido de hardware, y daba valores de
    40.000 a 800.000 — que el trigger interpretaba como movimiento
    permanente (falso positivo continuo).

    Ahora `filtrar_señal_butterworth` informa explícitamente el
    resultado del filtrado con un código `ESTADO_FILTRO_*`, y
    `DetectorMovimiento.procesar_ventana` inhibe el trigger cuando la
    ventana no fue filtrada: devuelve `movimiento_detectado=False`, no
    toca la base de datos y mantiene el estado del flanco tal como
    estaba. La varianza cruda se sigue reportando (con
    `filtro_aplicado=False`) para que la telemetría la muestre como
    diagnóstico, pero nunca dispara un evento.

Diseño modular:
    Las funciones de procesamiento de señal (`filtrar_señal_butterworth`,
    `calcular_varianza_promedio`, `evaluar_trigger_movimiento`) son puras:
    no dependen de la base de datos ni tienen efectos secundarios, y por
    lo tanto son fácilmente testeables de forma aislada. La integración
    con la persistencia (requisito 4) vive exclusivamente en la clase
    `DetectorMovimiento`, que es la única responsable de manejar el
    estado entre ventanas sucesivas (necesario para detectar el flanco
    ascendente) e invocar `insertar_evento_movimiento`.

Requisitos:
    pip install numpy scipy

Autor: Trabajo Integrador Final - Módulo de Procesamiento de Señal (MVP 2)
"""

import logging
from typing import Optional, Tuple

import numpy as np
from scipy.ndimage import median_filter
from scipy.signal import butter, sosfiltfilt

# ---------------------------------------------------------------------------
# Import robusto de la capa de persistencia
# ---------------------------------------------------------------------------
# Se intenta primero el import absoluto normal (funciona si el proyecto se
# ejecuta como paquete, ej. "python -m src.processing.signal_filter" desde
# la raíz, o si la raíz del proyecto ya está en PYTHONPATH). Si falla
# (por ejemplo al correr "python src/processing/signal_filter.py" de forma
# standalone), se agrega la raíz del proyecto a sys.path y se reintenta.
try:
    from src.database.database import insertar_evento_movimiento
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    _raiz_proyecto = Path(__file__).resolve().parents[2]
    if str(_raiz_proyecto) not in sys.path:
        sys.path.insert(0, str(_raiz_proyecto))
    from src.database.database import insertar_evento_movimiento

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("signal_filter")

# ---------------------------------------------------------------------------
# Constantes del pipeline de procesamiento
# ---------------------------------------------------------------------------

# Frecuencia de muestreo (paquetes CSI por segundo) de FALLBACK.
#
# Historial: originalmente este valor estaba en 100 Hz (una referencia
# genérica de trabajos de Wi-Fi sensing), pero la medición en vivo con
# la Raspberry Pi real mostró una tasa efectiva de ~650-690 Hz. Ese
# desfasaje hacía que el filtro Butterworth diseñara su banda de paso
# sobre una frecuencia de Nyquist equivocada (50 Hz asumidos vs. ~325 Hz
# reales), dejando pasar prácticamente todo el ruido de alta frecuencia
# sin atenuar y disparando la varianza a valores absurdos (>80.000),
# lo que a su vez dejaba el trigger trabado en `True` para siempre.
#
# La solución de fondo NO es hardcodear 650 Hz: las mediciones en vivo
# dieron valores distintos (686.0 Hz, 659.9 Hz, y 2-15 Hz con tráfico de
# `ping`), señal de que la tasa real depende del tráfico en el canal.
# Por eso `DetectorMovimiento.procesar_ventana()` recibe la `fs` REAL de
# cada ventana (medida por `src/main.py` a partir de los timestamps del
# propio stream pcap) y la usa para recalcular los coeficientes del
# filtro en cada llamada. Este valor de acá queda como red de
# seguridad, únicamente para los casos en que no hay timestamps reales
# disponibles (por ejemplo, el bloque de demostración de este archivo).
FRECUENCIA_MUESTREO_DEFAULT_HZ = 650.0

# Banda de paso del filtro Butterworth: frecuencias típicas de
# movimiento humano (caminar, gesticular) en sensado Wi-Fi CSI. Por
# debajo de este rango queda la componente DC / reflexiones estáticas
# del entorno; por encima, ruido blanco de alta frecuencia del hardware.
FRECUENCIA_CORTE_BAJA_HZ = 0.5
FRECUENCIA_CORTE_ALTA_HZ = 2.5

# Orden del filtro Butterworth. Un orden mayor logra una transición más
# abrupta entre bandas mas exige más muestras mínimas para poder
# aplicarse (ver `filtrar_señal_butterworth`).
ORDEN_FILTRO_DEFAULT = 4

# fs mínima a partir de la cual se confía en el filtrado.
#
# El límite teórico (Nyquist > 2.5 Hz, o sea fs > 5 Hz) NO alcanza en la
# práctica, por dos motivos:
#   1. No hay filtro anti-aliasing antes del "muestreo": cada paquete
#      CSI es una muestra instantánea del canal. Toda la energía por
#      encima de fs/2 (ruido de hardware, AGC, vibraciones) se pliega
#      dentro de la banda 0.5-2.5 Hz y es indistinguible del movimiento.
#   2. El diseño IIR asume muestreo UNIFORME. Con tasas bajas generadas
#      por tráfico esporádico (ping, beacons) el intervalo entre
#      paquetes tiene un jitter comparable al propio período, y la fs
#      "promedio" de la ventana deja de describir la señal.
# 30 Hz deja Nyquist a 6x la frecuencia de corte superior. Es un
# criterio de ingeniería ajustable, no un valor teórico: con el tráfico
# controlado recomendado (iperf3 UDP a ~200 pps) se trabaja muy por
# encima de este piso.
FS_MINIMA_CONFIABLE_HZ = 30.0

# ---------------------------------------------------------------------------
# Preprocesamiento de amplitudes (antes del filtro)
# ---------------------------------------------------------------------------
# Subportadoras ÚTILES para CSI a 20 MHz (64 bins de FFT, en el orden
# natural en que los entrega Nexmon: 0 = DC, 1..31 positivas, 32..63
# negativas).
#
# Al decodificar una trama real de esta misma placa (la de
# utils/generar_pcap.py) se ve que los bins 0 (DC) y 28..35 (guarda y
# bordes de banda) NO contienen canal sino valores basura del chip, de
# hasta ~33.000, contra ~300-600 de las subportadoras de datos. Esos
# pocos bins dominaban por completo la "varianza promedio": cambian de
# forma errática entre tramas (y según la trama sea legacy 802.11a/g,
# con datos en ±1..±26, o HT/802.11n, con datos en ±1..±28), y producían
# varianzas de miles a decenas de miles con saltos bruscos, sin relación
# con el movimiento.
#
# Se conservan sólo ±1..±26 (índices 1..26 y 38..63): son las 52
# subportadoras que tienen canal real en AMBOS tipos de trama, así el
# conjunto no depende de qué tipo de trama transmita el módem.
SUBPORTADORAS_UTILES_20MHZ = np.r_[1:27, 38:64]

# Normalización por paquete: cada vector de amplitudes se divide por su
# media (sobre las subportadoras útiles) y se expresa en porcentaje.
# Elimina los saltos de escala COMUNES a todas las subportadoras de una
# trama (ganancia automática del receptor, potencia de transmisión, MCS
# distinto según a qué cliente le hable el módem), que no son movimiento
# pero inflan la varianza. Lo que queda es la FORMA del canal en
# frecuencia, que es lo que perturba un cuerpo en movimiento.
NORMALIZAR_POR_PAQUETE = True

# Rechazo de paquetes atípicos POR FORMA (antes del Hampel).
#
# En vivo se observaron falsos positivos confirmados causados por
# RÁFAGAS de varios paquetes corruptos seguidos (probablemente tramas del
# módem con otra configuración de transmisión). El Hampel, con ventana de
# 7, sólo puede limpiar hasta 3 consecutivos; una ráfaga de 6 paquetes
# producía varianza ~14 y una de 15, ~85 (contra ~2 de un movimiento real),
# y como la ráfaga permanece dentro de la ventana deslizante durante ~2 s,
# completaba la confirmación de 3 ventanas.
#
# Criterio: cada paquete (ya normalizado, en %) se compara con el perfil
# MEDIANO de la ventana. Su desvío es el promedio, sobre las
# subportadoras, de |paquete - perfil_mediano|. Se marca atípico si su
# desvío supera a la vez:
#   - FACTOR_RECHAZO_PAQUETE veces el desvío típico (mediana) de los
#     paquetes de esa misma ventana, y
#   - DESVIO_MINIMO_RECHAZO_PCT en términos absolutos.
# Un movimiento real deforma el perfil de forma GRADUAL y a todos los
# paquetes de la ventana por igual, así que sube también el desvío
# típico de referencia y no dispara el rechazo; un paquete corrupto se
# aparta del resto de golpe. Los paquetes atípicos se reemplazan por el
# perfil mediano (no se eliminan, para no romper el muestreo uniforme).
# Si más de la mitad de la ventana resultara atípica, no se toca nada:
# en ese caso la "mediana" ya no representa el estado normal.
FACTOR_RECHAZO_PAQUETE = 5.0
DESVIO_MINIMO_RECHAZO_PCT = 10.0

# Filtro de Hampel en el eje temporal (por subportadora): reemplaza por
# la mediana local cada muestra que se aleja más de N desvíos robustos
# (MAD) de ella. Elimina impulsos de una o pocas tramas (tramas
# corruptas, picos de AGC) antes de que el pasabanda los "desparrame"
# sobre varias ventanas.
HAMPEL_VENTANA_MUESTRAS = 7     # ~50 ms a ~140 Hz
HAMPEL_N_SIGMAS = 3.0


def rechazar_paquetes_atipicos(
    matriz: np.ndarray,
    factor: float = FACTOR_RECHAZO_PAQUETE,
    desvio_minimo_pct: float = DESVIO_MINIMO_RECHAZO_PCT,
) -> Tuple[np.ndarray, int]:
    """
    Reemplaza por el perfil mediano de la ventana los paquetes cuya forma
    se aparta bruscamente del resto (ver `FACTOR_RECHAZO_PAQUETE`).
    Espera amplitudes ya normalizadas por paquete (en %).

    Returns:
        Tupla (matriz_limpia, cantidad_de_paquetes_reemplazados).
    """
    if matriz.shape[0] < 3:
        return matriz, 0

    perfil_mediano = np.median(matriz, axis=0)
    desvio_por_paquete = np.mean(np.abs(matriz - perfil_mediano), axis=1)
    desvio_tipico = float(np.median(desvio_por_paquete))
    limite = max(factor * desvio_tipico, desvio_minimo_pct)

    atipicos = desvio_por_paquete > limite
    n_atipicos = int(atipicos.sum())
    if n_atipicos == 0 or n_atipicos > matriz.shape[0] // 2:
        return matriz, 0

    matriz = matriz.copy()
    matriz[atipicos] = perfil_mediano
    return matriz, n_atipicos


def preprocesar_amplitudes(
    matriz_amplitud: np.ndarray,
    normalizar: bool = NORMALIZAR_POR_PAQUETE,
    hampel_ventana: int = HAMPEL_VENTANA_MUESTRAS,
    hampel_n_sigmas: float = HAMPEL_N_SIGMAS,
    rechazar_atipicos: bool = True,
    devolver_conteo: bool = False,
):
    """
    Limpia la matriz de amplitudes CSI (n_paquetes, n_subportadoras)
    antes del pasabanda:

        1. Descarta los bins sin canal (DC, guarda, bordes) si la matriz
           tiene 64 subportadoras (20 MHz). Para otros anchos de banda se
           conservan todas (todavía no validado con hardware).
        2. Normaliza cada paquete por su amplitud media (en %), si
           `normalizar` es True.
        3. Reemplaza los paquetes atípicos por forma (ráfagas de tramas
           corruptas), si `rechazar_atipicos` es True y se normalizó.
        4. Aplica un filtro de Hampel a lo largo del tiempo, si
           `hampel_ventana` >= 3.

    Función pura, sin efectos secundarios. Devuelve una matriz nueva o,
    si `devolver_conteo` es True, la tupla (matriz, n_paquetes_atipicos).
    """
    if matriz_amplitud.size == 0 or matriz_amplitud.ndim != 2:
        return (matriz_amplitud, 0) if devolver_conteo else matriz_amplitud

    matriz = np.asarray(matriz_amplitud, dtype=np.float64)

    if matriz.shape[1] == 64:
        matriz = matriz[:, SUBPORTADORAS_UTILES_20MHZ]

    if normalizar:
        media_por_paquete = matriz.mean(axis=1, keepdims=True)
        media_por_paquete[media_por_paquete <= 0] = 1.0  # paquete nulo: no dividir por 0
        matriz = 100.0 * matriz / media_por_paquete

    n_atipicos = 0
    if rechazar_atipicos and normalizar:
        matriz, n_atipicos = rechazar_paquetes_atipicos(matriz)

    if hampel_ventana >= 3 and matriz.shape[0] >= hampel_ventana:
        # IMPORTANTE: mode="mirror" y NO "nearest". Con "nearest", el
        # borde se rellena REPITIENDO la última muestra; si justo el
        # paquete más reciente de la ventana es un paquete corrupto, el
        # relleno lo replica 3 veces y el corrupto pasa a ser mayoría en
        # su propia vecindad: la mediana local ES el valor corrupto y el
        # Hampel no lo detecta. El pasabanda (sosfiltfilt) amplifica
        # además lo que hay en los bordes, y el resultado era un pico de
        # varianza de 40 a 1.600 en UNA sola ventana (en la siguiente el
        # paquete ya no está en el borde y se limpia bien), observado en
        # vivo como "Pico descartado: 1 ventana(s)". Con "mirror" el
        # relleno refleja las muestras vecinas sin repetir la del borde,
        # y el paquete corrupto queda en minoría como cualquier otro.
        mediana = median_filter(matriz, size=(hampel_ventana, 1), mode="mirror")
        desvio_abs = np.abs(matriz - mediana)
        mad = median_filter(desvio_abs, size=(hampel_ventana, 1), mode="mirror")
        limite = hampel_n_sigmas * 1.4826 * mad
        atipicos = desvio_abs > np.maximum(limite, 1e-12)
        matriz = np.where(atipicos, mediana, matriz)

    return (matriz, n_atipicos) if devolver_conteo else matriz


# ---------------------------------------------------------------------------
# Confirmación temporal del trigger (anti-picos) + histéresis
# ---------------------------------------------------------------------------
# Las ventanas de análisis (2 s, avance 0.2 s en main.py) se solapan en un
# 90%, así que un movimiento humano real aparece obligatoriamente en
# VARIAS ventanas consecutivas, con una subida y una bajada graduales. Un
# salto en una única ventana aislada es, casi siempre, un impulso del
# hardware (ajuste de AGC, trama corrupta) y no una persona. Por eso:
#
#   - ENTRADA: el estado pasa a "movimiento" recién cuando
#     VENTANAS_CONFIRMACION_ENTRADA ventanas válidas SEGUIDAS superan el
#     umbral (3 ventanas ≈ 0.6 s de movimiento sostenido).
#   - SALIDA: con histéresis. Para volver a reposo, la varianza tiene que
#     caer por debajo de umbral * FACTOR_HISTERESIS durante
#     VENTANAS_CONFIRMACION_SALIDA ventanas seguidas. Así, una varianza
#     que oscila justo alrededor del umbral no genera una ráfaga de
#     eventos (flapping) en la base de datos.
VENTANAS_CONFIRMACION_ENTRADA_DEFAULT = 3
VENTANAS_CONFIRMACION_SALIDA_DEFAULT = 5
FACTOR_HISTERESIS_DEFAULT = 0.7

# ---------------------------------------------------------------------------
# Códigos de resultado del filtrado (viajan por telemetría y logs)
# ---------------------------------------------------------------------------
ESTADO_FILTRO_SOS_OK = "SOS_OK"
ESTADO_FILTRO_VENTANA_VACIA = "CRUDA_VENTANA_VACIA"
ESTADO_FILTRO_FS_INSUFICIENTE = "CRUDA_FS_INSUFICIENTE"
ESTADO_FILTRO_MUESTRAS_INSUFICIENTES = "CRUDA_MUESTRAS_INSUFICIENTES"
ESTADO_FILTRO_ERROR_NUMERICO = "CRUDA_ERROR_NUMERICO"

# Descripciones legibles para logs y Dashboard.
DESCRIPCION_ESTADO_FILTRO = {
    ESTADO_FILTRO_SOS_OK: "Filtrada (Butterworth SOS)",
    ESTADO_FILTRO_VENTANA_VACIA: "Ventana vacía",
    ESTADO_FILTRO_FS_INSUFICIENTE: "fs real demasiado baja",
    ESTADO_FILTRO_MUESTRAS_INSUFICIENTES: "Muy pocas muestras en la ventana",
    ESTADO_FILTRO_ERROR_NUMERICO: "Salida del filtro no finita",
}


def filtro_fue_aplicado(estado_filtro: str) -> bool:
    """True si el código de estado corresponde a una ventana efectivamente filtrada."""
    return estado_filtro == ESTADO_FILTRO_SOS_OK


def _padlen_minimo_sosfiltfilt(sos: np.ndarray) -> int:
    """
    Replica el cálculo del `padlen` por defecto que usa
    `scipy.signal.sosfiltfilt`. La señal debe tener ESTRICTAMENTE más
    muestras que este valor a lo largo del eje filtrado; si no, scipy
    lanza ValueError. Calcularlo de antemano permite informar en el log
    cuántas muestras faltan, en lugar de sólo atrapar la excepción.
    """
    n_taps = 2 * sos.shape[0] + 1
    n_taps -= min(int((sos[:, 2] == 0).sum()), int((sos[:, 5] == 0).sum()))
    return 3 * n_taps


# ---------------------------------------------------------------------------
# 1. Filtrado digital
# ---------------------------------------------------------------------------
def filtrar_señal_butterworth(
    matriz_amplitud: np.ndarray,
    frecuencia_muestreo: float = FRECUENCIA_MUESTREO_DEFAULT_HZ,
    freq_corte_baja: float = FRECUENCIA_CORTE_BAJA_HZ,
    freq_corte_alta: float = FRECUENCIA_CORTE_ALTA_HZ,
    orden: int = ORDEN_FILTRO_DEFAULT,
    fs_minima: float = FS_MINIMA_CONFIABLE_HZ,
) -> Tuple[np.ndarray, str]:
    """
    Aplica un filtro Butterworth pasabanda, subportadora por
    subportadora, a lo largo del eje temporal (paquetes) de la matriz de
    amplitud CSI, e informa explícitamente si pudo hacerlo.

    El pasabanda cumple una doble función:
        - Elimina la componente continua (DC) y las variaciones muy
          lentas propias de un entorno estático (paredes, muebles), que
          concentran su energía cerca de 0 Hz.
        - Elimina el ruido blanco de alta frecuencia propio del
          hardware Wi-Fi, preservando la banda de movimiento humano.

    Se utiliza `scipy.signal.sosfiltfilt` (filtrado de fase cero sobre
    secciones de segundo orden) con `axis=0`, para filtrar todas las
    columnas (subportadoras) de forma vectorizada en una sola llamada.

    Args:
        matriz_amplitud: matriz (n_paquetes, n_subportadoras) de
            amplitudes CSI, tal como la produce `extraer_csi`.
        frecuencia_muestreo: tasa efectiva de paquetes CSI por segundo (Hz).
        freq_corte_baja: frecuencia de corte inferior del pasabanda (Hz).
        freq_corte_alta: frecuencia de corte superior del pasabanda (Hz).
        orden: orden del filtro Butterworth.
        fs_minima: fs por debajo de la cual no se confía en el filtrado
            (ver `FS_MINIMA_CONFIABLE_HZ`).

    Returns:
        Tupla (matriz, estado_filtro):
            - matriz: la matriz filtrada si estado_filtro es
              `ESTADO_FILTRO_SOS_OK`; en cualquier otro caso, la matriz
              de entrada SIN modificar.
            - estado_filtro: uno de los códigos `ESTADO_FILTRO_*`.
        Nunca lanza excepción: degrada de forma controlada para no
        interrumpir el pipeline en vivo. Los motivos se loguean a nivel
        DEBUG (el orquestador decide cuándo avisar a nivel WARNING, para
        no inundar la consola a ~5 ventanas/seg).
    """
    if matriz_amplitud.size == 0:
        logger.debug("Matriz de amplitud vacía: no hay nada para filtrar.")
        return matriz_amplitud, ESTADO_FILTRO_VENTANA_VACIA

    n_paquetes = matriz_amplitud.shape[0]

    if frecuencia_muestreo is None or frecuencia_muestreo < fs_minima:
        logger.debug(
            f"fs={frecuencia_muestreo} Hz < fs mínima confiable ({fs_minima} Hz): "
            f"no se aplica el filtro."
        )
        return matriz_amplitud, ESTADO_FILTRO_FS_INSUFICIENTE

    nyquist = frecuencia_muestreo / 2.0

    if freq_corte_alta >= nyquist:
        freq_corte_alta_ajustada = nyquist * 0.99
        logger.debug(
            f"freq_corte_alta ({freq_corte_alta} Hz) >= Nyquist ({nyquist} Hz) "
            f"para fs={frecuencia_muestreo} Hz. Se ajusta a "
            f"{freq_corte_alta_ajustada:.3f} Hz."
        )
        freq_corte_alta = freq_corte_alta_ajustada

    # Guarda de seguridad: si la fs es tan baja que la banda de paso queda
    # vacía o invertida, scipy.signal.butter() lanza "Wn[0] must be less
    # than Wn[1]". Con FS_MINIMA_CONFIABLE_HZ por encima de 5 Hz esto ya
    # no debería ocurrir, pero se conserva por si alguien baja fs_minima.
    if freq_corte_baja >= freq_corte_alta:
        logger.debug(
            f"Banda de paso vacía para fs={frecuencia_muestreo:.3f} Hz "
            f"(Nyquist={nyquist:.3f} Hz)."
        )
        return matriz_amplitud, ESTADO_FILTRO_FS_INSUFICIENTE

    baja_normalizada = freq_corte_baja / nyquist
    alta_normalizada = freq_corte_alta / nyquist

    # IMPORTANTE: se pide la representación en Second-Order Sections
    # (SOS) en lugar de los coeficientes de función de transferencia
    # (b, a). Para un pasabanda de banda MUY angosta como este (0.5-2.5
    # Hz sobre una Nyquist de cientos de Hz, frecuencias normalizadas del
    # orden de 0.0015-0.0077), la forma (b, a) es numéricamente
    # inestable: los errores de redondeo al expandir el polinomio empujan
    # algunos polos fuera del círculo unitario (se verificó con
    # scipy.signal.tf2zpk: 3 de 8 polos con radio > 1.0 en este caso
    # concreto). La cascada SOS es la forma estándar de evitarlo.
    sos = butter(orden, [baja_normalizada, alta_normalizada], btype="bandpass", output="sos")

    padlen = _padlen_minimo_sosfiltfilt(sos)
    if n_paquetes <= padlen:
        logger.debug(
            f"Ventana de {n_paquetes} paquetes insuficiente para sosfiltfilt "
            f"(orden {orden}): se necesitan más de {padlen}."
        )
        return matriz_amplitud, ESTADO_FILTRO_MUESTRAS_INSUFICIENTES

    try:
        # axis=0 -> filtra a lo largo del tiempo, columna por columna
        # (subportadora por subportadora), en una única operación vectorizada.
        matriz_filtrada = sosfiltfilt(sos, matriz_amplitud, axis=0)
    except ValueError as e:
        # No debería ocurrir tras el chequeo de padlen; se mantiene como
        # red de seguridad ante cambios internos de scipy.
        logger.debug(f"sosfiltfilt falló sobre {n_paquetes} paquetes: {e}")
        return matriz_amplitud, ESTADO_FILTRO_MUESTRAS_INSUFICIENTES

    if not np.all(np.isfinite(matriz_filtrada)):
        logger.debug("La salida del filtro contiene NaN/Inf.")
        return matriz_amplitud, ESTADO_FILTRO_ERROR_NUMERICO

    return matriz_filtrada, ESTADO_FILTRO_SOS_OK


# ---------------------------------------------------------------------------
# 2. Cálculo de varianza
# ---------------------------------------------------------------------------
def calcular_varianza_promedio(matriz_filtrada: np.ndarray) -> float:
    """
    Calcula la métrica de "agitación del canal": el promedio de las
    varianzas de amplitud de todas las subportadoras, dentro de la
    ventana temporal analizada.

    Esta es la métrica final que el módulo de persistencia guarda como
    `varianza_maxima` en `registro_movimiento` y que se compara contra
    el `umbral_sensibilidad` configurado por el usuario.

    Args:
        matriz_filtrada: matriz (n_paquetes, n_subportadoras) de
            amplitud ya filtrada (ver `filtrar_señal_butterworth`).

    Returns:
        float con el promedio de las varianzas por subportadora.
        0.0 si la matriz está vacía.
    """
    if matriz_filtrada.size == 0:
        return 0.0

    varianza_por_subportadora = np.var(matriz_filtrada, axis=0)
    return float(np.mean(varianza_por_subportadora))


# ---------------------------------------------------------------------------
# 3. Lógica de umbral (trigger)
# ---------------------------------------------------------------------------
def evaluar_trigger_movimiento(varianza_promedio: float, umbral: float) -> Tuple[bool, float]:
    """
    Evalúa si la métrica de varianza promedio supera el umbral de
    sensibilidad, disparando (o no) el estado de movimiento detectado.

    Sólo tiene sentido sobre una varianza calculada a partir de una
    ventana FILTRADA; `DetectorMovimiento` se encarga de no llamarla en
    caso contrario.

    Args:
        varianza_promedio: métrica de agitación del canal (ver
            `calcular_varianza_promedio`).
        umbral: umbral de sensibilidad configurado por el usuario
            (`configuracion_sistema.umbral_sensibilidad`).

    Returns:
        Tupla (movimiento_detectado: bool, varianza_promedio: float).
    """
    movimiento_detectado = varianza_promedio > umbral
    return movimiento_detectado, varianza_promedio


# ---------------------------------------------------------------------------
# 4. Orquestador con estado + integración con la base de datos
# ---------------------------------------------------------------------------
class DetectorMovimiento:
    """
    Orquesta el pipeline completo de detección de movimiento para un
    usuario puntual: filtra cada ventana de amplitud CSI, calcula la
    varianza promedio, evalúa el trigger (sólo si la ventana fue
    filtrada) con confirmación temporal e histéresis, y persiste el
    evento en la base de datos únicamente en el flanco ascendente del
    estado CONFIRMADO (reposo -> movimiento).

    Máquina de estados (sólo avanza con ventanas válidas/filtradas):

        REPOSO --(N_entrada ventanas seguidas con varianza > umbral)--> MOVIMIENTO
               [al confirmar: se registra UN evento en la BD]
        MOVIMIENTO --(N_salida ventanas seguidas con varianza <
                      umbral * factor_histeresis)--> REPOSO

    Una ventana sobre el umbral que todavía no completó la racha de
    entrada queda como "candidata" (se informa en el resultado para que
    el Dashboard pueda mostrar "Confirmando 1/3..."), pero no cambia el
    estado ni toca la base de datos.

    Se implementa como clase (y no como función suelta) porque necesita
    recordar el estado y las rachas entre llamadas sucesivas de
    `procesar_ventana`.

    Uso típico (dentro del loop principal del sistema):
        detector = DetectorMovimiento(usuario_id=3, umbral_sensibilidad=450.0)
        while True:
            ventana, fs = ...                    # nueva ventana de CSI
            resultado = detector.procesar_ventana(ventana, fs)
    """

    def __init__(
        self,
        usuario_id: int,
        umbral_sensibilidad: float,
        frecuencia_muestreo: float = FRECUENCIA_MUESTREO_DEFAULT_HZ,
        freq_corte_baja: float = FRECUENCIA_CORTE_BAJA_HZ,
        freq_corte_alta: float = FRECUENCIA_CORTE_ALTA_HZ,
        orden_filtro: int = ORDEN_FILTRO_DEFAULT,
        fs_minima: float = FS_MINIMA_CONFIABLE_HZ,
        ventanas_confirmacion_entrada: int = VENTANAS_CONFIRMACION_ENTRADA_DEFAULT,
        ventanas_confirmacion_salida: int = VENTANAS_CONFIRMACION_SALIDA_DEFAULT,
        factor_histeresis: float = FACTOR_HISTERESIS_DEFAULT,
    ) -> None:
        """
        Args:
            usuario_id: ID del usuario dueño de esta sesión de detección
                (se usa para vincular los eventos en la base de datos).
            umbral_sensibilidad: umbral de varianza (de ENTRADA) a partir
                del cual una ventana cuenta como candidata a movimiento.
                Se puede reasignar en caliente (lo hace el hilo de
                relectura de configuración de main.py).
            frecuencia_muestreo: tasa de paquetes CSI por segundo (Hz)
                de fallback, si el llamador no informa la fs real.
            freq_corte_baja / freq_corte_alta: banda de paso del filtro.
            orden_filtro: orden del filtro Butterworth.
            fs_minima: fs mínima confiable para aplicar el filtro.
            ventanas_confirmacion_entrada: ventanas válidas seguidas
                sobre el umbral necesarias para confirmar movimiento.
            ventanas_confirmacion_salida: ventanas válidas seguidas bajo
                el umbral de salida necesarias para volver a reposo.
            factor_histeresis: umbral de salida = umbral * este factor
                (entre 0 y 1).
        """
        self.usuario_id = usuario_id
        self.umbral_sensibilidad = umbral_sensibilidad
        self.frecuencia_muestreo = frecuencia_muestreo
        self.freq_corte_baja = freq_corte_baja
        self.freq_corte_alta = freq_corte_alta
        self.orden_filtro = orden_filtro
        self.fs_minima = fs_minima
        self.ventanas_confirmacion_entrada = max(1, int(ventanas_confirmacion_entrada))
        self.ventanas_confirmacion_salida = max(1, int(ventanas_confirmacion_salida))
        self.factor_histeresis = min(max(float(factor_histeresis), 0.0), 1.0)

        # Estado CONFIRMADO. Arranca en reposo.
        self._en_movimiento: bool = False
        # Rachas de ventanas válidas consecutivas.
        self._racha_sobre_umbral: int = 0
        self._racha_bajo_umbral_salida: int = 0
        # Varianza máxima observada durante la racha de entrada actual
        # (es la que se persiste como `varianza_maxima` del evento).
        self._varianza_maxima_racha: float = 0.0
        # Paquetes atípicos reemplazados en la última ventana (diagnóstico).
        self._ultimo_n_atipicos: int = 0

    @property
    def umbral_salida(self) -> float:
        """Umbral por debajo del cual se cuenta una ventana para volver a reposo."""
        return float(self.umbral_sensibilidad) * self.factor_histeresis

    def procesar_ventana(
        self, matriz_amplitud: np.ndarray, frecuencia_muestreo: Optional[float] = None
    ) -> dict:
        """
        Ejecuta el pipeline completo sobre una ventana de amplitudes CSI
        y, si corresponde, registra el evento en la base de datos.

        Args:
            matriz_amplitud: matriz (n_paquetes, n_subportadoras) de
                amplitudes CSI crudas de la ventana actual.
            frecuencia_muestreo: fs REAL de esta ventana en particular,
                medida por el llamador a partir de timestamps reales. Si
                se provee, tiene prioridad sobre la fs de fallback con la
                que se construyó este detector.

        Returns:
            dict con:
                - "movimiento_detectado" (bool): estado CONFIRMADO (con
                  confirmación temporal e histéresis). En una ventana no
                  filtrada se informa el estado vigente sin modificarlo.
                - "supera_umbral" (bool): si ESTA ventana superó el
                  umbral de entrada (decisión instantánea, sin
                  confirmar). Siempre False si la ventana no se filtró.
                - "ventanas_sobre_umbral" (int): largo de la racha
                  actual de ventanas válidas sobre el umbral.
                - "ventanas_confirmacion" (int): racha necesaria para
                  confirmar movimiento.
                - "umbral_salida" (float): umbral de salida vigente.
                - "varianza_promedio" (float): de la señal filtrada si
                  `filtro_aplicado`, o de la señal CRUDA en caso
                  contrario (sólo informativa, no comparable).
                - "evento_registrado" (bool): True si esta ventana
                  confirmó un movimiento nuevo y el evento se persistió.
                - "frecuencia_muestreo_usada" (float): la fs que se usó
                  para diseñar (o intentar diseñar) el filtro.
                - "filtro_aplicado" (bool): True si la ventana pasó por
                  el pasabanda SOS.
                - "estado_filtro" (str): código `ESTADO_FILTRO_*`.
                - "n_paquetes" (int): paquetes en la ventana.
        """
        fs_efectiva = (
            frecuencia_muestreo if frecuencia_muestreo is not None else self.frecuencia_muestreo
        )
        n_paquetes = int(matriz_amplitud.shape[0]) if matriz_amplitud.ndim > 0 else 0

        # Limpieza previa (bins basura, escala por paquete, impulsos). Se
        # hace ANTES de decidir si la ventana se puede filtrar, para que
        # la varianza cruda reportada en ventanas no filtradas también
        # sea la de la señal limpia.
        matriz_limpia, self._ultimo_n_atipicos = preprocesar_amplitudes(
            matriz_amplitud, devolver_conteo=True
        )

        matriz_procesada, estado_filtro = filtrar_señal_butterworth(
            matriz_limpia,
            frecuencia_muestreo=fs_efectiva,
            freq_corte_baja=self.freq_corte_baja,
            freq_corte_alta=self.freq_corte_alta,
            orden=self.orden_filtro,
            fs_minima=self.fs_minima,
        )
        filtro_aplicado = filtro_fue_aplicado(estado_filtro)
        varianza_promedio = calcular_varianza_promedio(matriz_procesada)

        if not filtro_aplicado:
            # Ventana inválida: la varianza cruda NO es comparable contra
            # el umbral. No se evalúa nada, no se toca la BD, y NO se
            # modifican el estado ni las rachas: quedan congelados hasta
            # la próxima ventana válida, para que una racha de ventanas
            # inválidas en medio de un movimiento no genere un evento
            # duplicado al recuperarse.
            return self._armar_resultado(
                varianza_promedio, fs_efectiva, filtro_aplicado, estado_filtro,
                n_paquetes, supera_umbral=False, evento_registrado=False,
            )

        supera_umbral, varianza_promedio = evaluar_trigger_movimiento(
            varianza_promedio, self.umbral_sensibilidad
        )
        evento_registrado = False

        if not self._en_movimiento:
            # --- REPOSO: acumular racha de entrada ---------------------
            if supera_umbral:
                self._racha_sobre_umbral += 1
                self._varianza_maxima_racha = max(self._varianza_maxima_racha, varianza_promedio)
            else:
                if self._racha_sobre_umbral > 0:
                    # Se informa a nivel INFO: es justamente el dato para
                    # diagnosticar falsos positivos (duración y magnitud de
                    # los picos que el filtro de confirmación frenó).
                    logger.info(
                        f"Pico descartado: {self._racha_sobre_umbral} ventana(s) sobre el "
                        f"umbral (máx {self._varianza_maxima_racha:.3f}), se necesitaban "
                        f"{self.ventanas_confirmacion_entrada} para confirmar."
                    )
                self._racha_sobre_umbral = 0
                self._varianza_maxima_racha = 0.0

            if self._racha_sobre_umbral >= self.ventanas_confirmacion_entrada:
                # Flanco ascendente del estado CONFIRMADO: único momento
                # en el que se persiste un evento nuevo.
                self._en_movimiento = True
                self._racha_bajo_umbral_salida = 0
                evento_registrado = self._registrar_evento(n_paquetes, fs_efectiva)
        else:
            # --- MOVIMIENTO: esperar racha de salida (con histéresis) ---
            self._racha_sobre_umbral = self._racha_sobre_umbral + 1 if supera_umbral else 0
            if varianza_promedio < self.umbral_salida:
                self._racha_bajo_umbral_salida += 1
            else:
                self._racha_bajo_umbral_salida = 0

            if self._racha_bajo_umbral_salida >= self.ventanas_confirmacion_salida:
                self._en_movimiento = False
                self._racha_sobre_umbral = 0
                self._racha_bajo_umbral_salida = 0
                self._varianza_maxima_racha = 0.0
                logger.info(
                    f"Fin de movimiento (usuario {self.usuario_id}): "
                    f"{self.ventanas_confirmacion_salida} ventanas seguidas bajo el "
                    f"umbral de salida ({self.umbral_salida:.2f})."
                )

        return self._armar_resultado(
            varianza_promedio, fs_efectiva, filtro_aplicado, estado_filtro,
            n_paquetes, supera_umbral=supera_umbral, evento_registrado=evento_registrado,
        )

    def _registrar_evento(self, n_paquetes: int, fs_efectiva: float) -> bool:
        """Persiste el evento de movimiento confirmado. Devuelve True si se guardó."""
        duracion_estimada = self._estimar_duracion_segundos(
            n_paquetes, frecuencia_muestreo=fs_efectiva
        )
        evento_id = insertar_evento_movimiento(
            usuario_id=self.usuario_id,
            varianza=self._varianza_maxima_racha,
            duracion=duracion_estimada,
        )
        if evento_id is not None:
            logger.info(
                f"Movimiento CONFIRMADO (usuario {self.usuario_id}) tras "
                f"{self.ventanas_confirmacion_entrada} ventanas seguidas sobre el umbral: "
                f"varianza_max={self._varianza_maxima_racha:.4f}, "
                f"duración≈{duracion_estimada}s -> evento #{evento_id} registrado."
            )
            return True

        logger.error(
            f"Movimiento confirmado (usuario {self.usuario_id}) pero no se "
            f"pudo registrar el evento en la base de datos."
        )
        return False

    def _armar_resultado(
        self,
        varianza_promedio: float,
        fs_efectiva: float,
        filtro_aplicado: bool,
        estado_filtro: str,
        n_paquetes: int,
        supera_umbral: bool,
        evento_registrado: bool,
    ) -> dict:
        return {
            "movimiento_detectado": self._en_movimiento,
            "supera_umbral": supera_umbral,
            "ventanas_sobre_umbral": self._racha_sobre_umbral,
            "ventanas_confirmacion": self.ventanas_confirmacion_entrada,
            "umbral_salida": self.umbral_salida,
            "varianza_promedio": varianza_promedio,
            "evento_registrado": evento_registrado,
            "frecuencia_muestreo_usada": fs_efectiva,
            "filtro_aplicado": filtro_aplicado,
            "estado_filtro": estado_filtro,
            "n_paquetes": n_paquetes,
            "paquetes_atipicos": self._ultimo_n_atipicos,
        }

    def _estimar_duracion_segundos(
        self, n_paquetes: int, frecuencia_muestreo: Optional[float] = None
    ) -> int:
        """
        Estima la duración del evento como la duración temporal de la
        ventana de paquetes analizada (n_paquetes / fs).

        Es una aproximación deliberadamente simple para el MVP. Una
        futura iteración podría acumular la duración real hasta detectar
        el flanco descendente antes de persistir el evento.
        """
        fs = frecuencia_muestreo if frecuencia_muestreo is not None else self.frecuencia_muestreo
        if fs is None or fs <= 0 or n_paquetes <= 0:
            return 0
        return max(1, round(n_paquetes / fs))

    def reiniciar_estado(self) -> None:
        """Reinicia el estado confirmado a reposo y vacía las rachas."""
        self._en_movimiento = False
        self._racha_sobre_umbral = 0
        self._racha_bajo_umbral_salida = 0
        self._varianza_maxima_racha = 0.0


# ---------------------------------------------------------------------------
# Prueba manual del módulo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Simulación de una secuencia de ventanas para mostrar la máquina de
    # estados: reposo -> pico aislado (descartado) -> movimiento sostenido
    # (confirmado tras 3 ventanas, 1 evento) -> fin del movimiento.
    FS_SIMULADA = 140.0        # Hz, similar a lo medido con iperf3
    N_SUBPORTADORAS = 64
    DURACION_VENTANA_SEG = 2
    UMBRAL_DEMO = 2.0

    n = int(FS_SIMULADA * DURACION_VENTANA_SEG)
    t = np.arange(n) / FS_SIMULADA
    rng = np.random.default_rng(seed=42)

    # Perfil de canal plausible + saltos de ganancia por paquete (AGC)
    # + bins basura en DC/guarda, como en las tramas reales de la placa.
    perfil = 400.0 + 150.0 * np.cos(np.linspace(0, 2 * np.pi, N_SUBPORTADORAS))
    patron_espacial = np.sin(np.linspace(0, 6 * np.pi, N_SUBPORTADORAS))

    def ventana(intensidad_movimiento: float) -> np.ndarray:
        m = perfil * (1 + 0.01 * rng.normal(size=(n, N_SUBPORTADORAS)))
        m *= rng.choice([1.0, 1.0, 1.0, 1.35, 0.8], size=(n, 1))   # AGC
        m[:, [0, 28, 29, 30, 31, 32, 33, 34, 35]] = rng.uniform(0, 35000, size=(n, 9))
        # El movimiento perturba el canal de forma SELECTIVA en frecuencia
        # (distinto en cada subportadora); una variación idéntica en todas
        # sería indistinguible de un cambio de ganancia y la normalización
        # la eliminaría a propósito.
        mov = intensidad_movimiento * np.sin(2 * np.pi * 1.2 * t)
        return m * (1 + mov[:, np.newaxis] * patron_espacial[np.newaxis, :])

    detector = DetectorMovimiento(usuario_id=1, umbral_sensibilidad=UMBRAL_DEMO)

    secuencia = (
        [("reposo", 0.0)] * 3
        + [("PICO aislado", 0.08)]
        + [("reposo", 0.0)] * 2
        + [("movimiento", 0.08)] * 5
        + [("reposo", 0.0)] * 6
    )

    print(f"umbral entrada={UMBRAL_DEMO}, umbral salida={detector.umbral_salida}, "
          f"confirmación={detector.ventanas_confirmacion_entrada} ventanas\n")
    for i, (etiqueta, amp) in enumerate(secuencia, start=1):
        r = detector.procesar_ventana(ventana(amp), frecuencia_muestreo=FS_SIMULADA)
        print(
            f"#{i:02d} {etiqueta:<13} var={r['varianza_promedio']:9.2f} "
            f"supera={str(r['supera_umbral']):<5} racha={r['ventanas_sobre_umbral']} "
            f"estado={'MOVIMIENTO' if r['movimiento_detectado'] else 'reposo':<10} "
            f"evento={r['evento_registrado']}"
        )
