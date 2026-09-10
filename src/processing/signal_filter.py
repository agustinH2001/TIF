"""
signal_filter.py
=================

Motor lógico de detección de movimiento del MVP 2.

Este módulo toma la matriz de amplitudes CSI producida por
`src.parser.parser_csi` (forma: n_paquetes x n_subportadoras) y ejecuta
el pipeline de procesamiento de señal que decide si hubo movimiento:

    1. Filtrado digital (Butterworth pasabanda) subportadora por
       subportadora, para quedarse únicamente con la banda de frecuencia
       típica del movimiento humano.
    2. Cálculo de la varianza promedio de la señal filtrada: la métrica
       de "agitación del canal".
    3. Evaluación de un trigger por umbral sobre esa métrica.
    4. Persistencia del evento en la base de datos, únicamente en el
       flanco ascendente de la detección (False -> True), para no
       duplicar el mismo evento de movimiento en cada ventana analizada.

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
# La solución de fondo NO es hardcodear 650 Hz: las dos mediciones en
# vivo ya dieron valores distintos (686.0 Hz y 659.9 Hz), señal de que
# la tasa real fluctúa según las condiciones de captura. Por eso
# `DetectorMovimiento.procesar_ventana()` ahora recibe la `fs` REAL de
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


# ---------------------------------------------------------------------------
# 1. Filtrado digital
# ---------------------------------------------------------------------------
def filtrar_señal_butterworth(
    matriz_amplitud: np.ndarray,
    frecuencia_muestreo: float = FRECUENCIA_MUESTREO_DEFAULT_HZ,
    freq_corte_baja: float = FRECUENCIA_CORTE_BAJA_HZ,
    freq_corte_alta: float = FRECUENCIA_CORTE_ALTA_HZ,
    orden: int = ORDEN_FILTRO_DEFAULT,
) -> np.ndarray:
    """
    Aplica un filtro Butterworth pasabanda, subportadora por
    subportadora, a lo largo del eje temporal (paquetes) de la matriz de
    amplitud CSI.

    El pasabanda cumple una doble función:
        - Elimina la componente continua (DC) y las variaciones muy
          lentas propias de un entorno estático (paredes, muebles), que
          concentran su energía cerca de 0 Hz.
        - Elimina el ruido blanco de alta frecuencia propio del
          hardware Wi-Fi, preservando la banda de movimiento humano.

    Se utiliza `scipy.signal.filtfilt` (filtrado de fase cero, aplicado
    hacia adelante y hacia atrás) para no introducir ningún desfasaje
    entre subportadoras, y se lo invoca con `axis=0` para filtrar todas
    las columnas (subportadoras) de forma vectorizada en una sola
    llamada, sin necesidad de iterar en Python.

    Args:
        matriz_amplitud: matriz (n_paquetes, n_subportadoras) de
            amplitudes CSI, tal como la produce `extraer_csi`.
        frecuencia_muestreo: tasa efectiva de paquetes CSI por segundo (Hz).
        freq_corte_baja: frecuencia de corte inferior del pasabanda (Hz).
        freq_corte_alta: frecuencia de corte superior del pasabanda (Hz).
        orden: orden del filtro Butterworth.

    Returns:
        np.ndarray de la misma forma que `matriz_amplitud`, filtrada.
        Si la matriz de entrada está vacía, o si la ventana temporal es
        demasiado corta para el orden de filtro solicitado, se devuelve
        la matriz de entrada sin modificar (con un warning en el log),
        en lugar de interrumpir el pipeline con una excepción.
    """
    if matriz_amplitud.size == 0:
        logger.warning("Matriz de amplitud vacía: no hay nada para filtrar.")
        return matriz_amplitud

    n_paquetes = matriz_amplitud.shape[0]
    nyquist = frecuencia_muestreo / 2.0

    if freq_corte_alta >= nyquist:
        freq_corte_alta_ajustada = nyquist * 0.99
        logger.warning(
            f"freq_corte_alta ({freq_corte_alta} Hz) >= Nyquist ({nyquist} Hz) "
            f"para fs={frecuencia_muestreo} Hz. Se ajusta a "
            f"{freq_corte_alta_ajustada:.3f} Hz."
        )
        freq_corte_alta = freq_corte_alta_ajustada

    # Guarda de seguridad: el ajuste de arriba sólo corrige el borde
    # SUPERIOR de la banda contra Nyquist. Si la fs real es tan baja que
    # ni siquiera el borde INFERIOR (freq_corte_baja) entra por debajo
    # del superior ya ajustado, la banda de paso queda vacía o invertida
    # y scipy.signal.butter() lanza "Wn[0] must be less than Wn[1]" —
    # esto se pudo reproducir en vivo con tráfico Wi-Fi muy escaso
    # (fs real de menos de 1 Hz, perfectamente posible con la ventana
    # por tiempo si hay huecos grandes entre paquetes). En ese caso no
    # hay ningún pasabanda válido que diseñar -haría falta muestrear más
    # rápido para distinguir la banda de interés-, así que se devuelve
    # la señal sin filtrar en vez de crashear todo el pipeline en vivo.
    if freq_corte_baja >= freq_corte_alta:
        logger.warning(
            f"La fs de esta ventana ({frecuencia_muestreo:.3f} Hz, Nyquist="
            f"{nyquist:.3f} Hz) es demasiado baja para el pasabanda "
            f"configurado ({FRECUENCIA_CORTE_BAJA_HZ}-{FRECUENCIA_CORTE_ALTA_HZ} Hz). "
            f"Se devuelve la señal sin filtrar."
        )
        return matriz_amplitud

    baja_normalizada = freq_corte_baja / nyquist
    alta_normalizada = freq_corte_alta / nyquist

    # IMPORTANTE: se pide la representación en Second-Order Sections
    # (SOS) en lugar de los coeficientes de función de transferencia
    # (b, a). Para un pasabanda de banda MUY angosta como este (0.5-2.5
    # Hz sobre una Nyquist de cientos de Hz a fs reales ~650Hz, es decir
    # frecuencias normalizadas del orden de 0.0015-0.0077), la forma
    # (b, a) es numéricamente inestable: los errores de redondeo al
    # expandir el polinomio empujan algunos polos fuera del círculo
    # unitario (se verificó con scipy.signal.tf2zpk: 3 de 8 polos con
    # radio > 1.0 en este caso concreto). Con ventanas cortas eso no se
    # nota, pero con ventanas largas (1300 muestras = 2s reales) el
    # filtro tiene tiempo de sobra para divergir exponencialmente,
    # disparando la varianza a valores absurdos (billones) incluso en
    # reposo. La cascada de secciones de segundo orden (SOS) es la
    # forma estándar de la industria para evitar este problema.
    sos = butter(orden, [baja_normalizada, alta_normalizada], btype="bandpass", output="sos")

    try:
        # axis=0 -> filtra a lo largo del tiempo, columna por columna
        # (subportadora por subportadora), en una única operación vectorizada.
        matriz_filtrada = sosfiltfilt(sos, matriz_amplitud, axis=0)
    except ValueError as e:
        # sosfiltfilt exige un mínimo de muestras (relacionado con el
        # orden del filtro) para poder aplicar su padding interno. Si la
        # ventana es demasiado corta, se prefiere degradar de forma
        # controlada antes que romper el pipeline completo.
        logger.warning(
            f"No se pudo aplicar el filtro sobre una ventana de "
            f"{n_paquetes} paquetes (orden {orden}): {e}. "
            f"Se devuelve la señal sin filtrar."
        )
        return matriz_amplitud

    return matriz_filtrada


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
        logger.warning("Matriz filtrada vacía: varianza promedio = 0.0")
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
    varianza promedio, evalúa el trigger, y persiste el evento en la
    base de datos únicamente en el flanco ascendente de la detección
    (transición False -> True), evitando registrar múltiples eventos
    para una misma racha de movimiento continuo.

    Se implementa como clase (y no como función suelta) porque, a
    diferencia de las funciones de procesamiento puro de este módulo,
    necesita recordar el estado del trigger entre llamadas sucesivas de
    `procesar_ventana`.

    Uso típico (dentro del loop principal del sistema):
        detector = DetectorMovimiento(usuario_id=3, umbral_sensibilidad=0.5,
                                       frecuencia_muestreo=100.0)
        while True:
            ventana = extraer_csi(...)          # nueva ventana de CSI
            resultado = detector.procesar_ventana(ventana)
            ...
    """

    def __init__(
        self,
        usuario_id: int,
        umbral_sensibilidad: float,
        frecuencia_muestreo: float = FRECUENCIA_MUESTREO_DEFAULT_HZ,
        freq_corte_baja: float = FRECUENCIA_CORTE_BAJA_HZ,
        freq_corte_alta: float = FRECUENCIA_CORTE_ALTA_HZ,
        orden_filtro: int = ORDEN_FILTRO_DEFAULT,
    ) -> None:
        """
        Args:
            usuario_id: ID del usuario dueño de esta sesión de detección
                (se usa para vincular los eventos en la base de datos).
            umbral_sensibilidad: umbral de varianza a partir del cual se
                considera que hubo movimiento.
            frecuencia_muestreo: tasa de paquetes CSI por segundo (Hz).
            freq_corte_baja / freq_corte_alta: banda de paso del filtro.
            orden_filtro: orden del filtro Butterworth.
        """
        self.usuario_id = usuario_id
        self.umbral_sensibilidad = umbral_sensibilidad
        self.frecuencia_muestreo = frecuencia_muestreo
        self.freq_corte_baja = freq_corte_baja
        self.freq_corte_alta = freq_corte_alta
        self.orden_filtro = orden_filtro

        # Estado del trigger en la ventana anterior. Arranca en False:
        # se asume que el sistema inicia en reposo.
        self._estado_anterior: bool = False

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
                medida por el llamador a partir de timestamps reales
                (por ejemplo, `src/main.py` la calcula a partir de los
                timestamps del stream pcap en vivo). Si se provee, tiene
                prioridad sobre la fs fija con la que se construyó este
                detector — es la forma correcta de operar en producción,
                donde la tasa real de llegada de paquetes puede fluctuar
                (carga de red, jitter de hardware, tráfico ambiente) y
                no hay ninguna garantía de que coincida con un valor
                asumido de antemano. Si se omite, se usa
                `self.frecuencia_muestreo` como antes.

        Returns:
            dict con:
                - "movimiento_detectado" (bool)
                - "varianza_promedio" (float)
                - "evento_registrado" (bool): True si esta ventana
                  disparó un flanco ascendente y el evento se persistió
                  correctamente en la base de datos.
                - "frecuencia_muestreo_usada" (float): la fs que
                  efectivamente se usó para diseñar el filtro en esta
                  llamada (útil para logging/telemetría).
        """
        fs_efectiva = (
            frecuencia_muestreo if frecuencia_muestreo is not None else self.frecuencia_muestreo
        )

        matriz_filtrada = filtrar_señal_butterworth(
            matriz_amplitud,
            frecuencia_muestreo=fs_efectiva,
            freq_corte_baja=self.freq_corte_baja,
            freq_corte_alta=self.freq_corte_alta,
            orden=self.orden_filtro,
        )
        varianza_promedio = calcular_varianza_promedio(matriz_filtrada)
        movimiento_detectado, varianza_promedio = evaluar_trigger_movimiento(
            varianza_promedio, self.umbral_sensibilidad
        )

        evento_registrado = False

        # Flanco ascendente: la ventana anterior estaba en reposo y esta
        # detecta movimiento. Es el único caso en el que se persiste un
        # nuevo evento, para no duplicar el mismo evento continuo en
        # cada ventana sucesiva mientras el movimiento se mantiene.
        if movimiento_detectado and not self._estado_anterior:
            duracion_estimada = self._estimar_duracion_segundos(
                matriz_amplitud.shape[0], frecuencia_muestreo=fs_efectiva
            )
            evento_id = insertar_evento_movimiento(
                usuario_id=self.usuario_id,
                varianza=varianza_promedio,
                duracion=duracion_estimada,
            )
            evento_registrado = evento_id is not None

            if evento_registrado:
                logger.info(
                    f"Movimiento detectado (usuario {self.usuario_id}): "
                    f"varianza={varianza_promedio:.4f}, "
                    f"duración≈{duracion_estimada}s -> evento #{evento_id} registrado."
                )
            else:
                logger.error(
                    f"Movimiento detectado (usuario {self.usuario_id}) pero no se "
                    f"pudo registrar el evento en la base de datos."
                )

        self._estado_anterior = movimiento_detectado

        return {
            "movimiento_detectado": movimiento_detectado,
            "varianza_promedio": varianza_promedio,
            "evento_registrado": evento_registrado,
            "frecuencia_muestreo_usada": fs_efectiva,
        }

    def _estimar_duracion_segundos(
        self, n_paquetes: int, frecuencia_muestreo: Optional[float] = None
    ) -> int:
        """
        Estima la duración del evento como la duración temporal de la
        ventana de paquetes analizada (n_paquetes / fs).

        Es una aproximación deliberadamente simple para el MVP: se
        registra la duración de la ventana en la que se detectó el
        inicio del movimiento. Una futura iteración podría, en cambio,
        acumular la duración real hasta detectar el flanco descendente
        (fin del movimiento) antes de persistir el evento.

        Args:
            n_paquetes: cantidad de paquetes en la ventana.
            frecuencia_muestreo: fs a usar para el cálculo; si se omite,
                se usa `self.frecuencia_muestreo`. Debe ser la misma fs
                efectiva con la que se filtró la ventana, para que la
                duración persistida sea consistente con el filtro
                aplicado.
        """
        fs = frecuencia_muestreo if frecuencia_muestreo is not None else self.frecuencia_muestreo
        if fs is None or fs <= 0 or n_paquetes <= 0:
            return 0
        return max(1, round(n_paquetes / fs))

    def reiniciar_estado(self) -> None:
        """Reinicia el estado del trigger a reposo (False)."""
        self._estado_anterior = False


# ---------------------------------------------------------------------------
# Prueba manual del módulo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # --- Parámetros de la simulación ---
    FS_SIMULADA = 100.0        # Hz: paquetes CSI por segundo
    N_SUBPORTADORAS = 64
    DURACION_VENTANA_SEG = 5
    USUARIO_ID_DEMO = 1
    UMBRAL_DEMO = 0.5

    n_paquetes = int(FS_SIMULADA * DURACION_VENTANA_SEG)
    t = np.arange(n_paquetes) / FS_SIMULADA

    rng = np.random.default_rng(seed=42)

    # Componente DC fuerte (reflexiones estáticas del entorno) + ruido
    # blanco de alta frecuencia propio del hardware. Común a ambos
    # escenarios; representa el canal "en reposo".
    dc = 100.0
    ruido_blanco = rng.normal(0, 0.5, size=(n_paquetes, N_SUBPORTADORAS))

    detector = DetectorMovimiento(
        usuario_id=USUARIO_ID_DEMO,
        umbral_sensibilidad=UMBRAL_DEMO,
        frecuencia_muestreo=FS_SIMULADA,
    )

    print("=" * 70)
    print("ESCENARIO 1: Entorno estático (sin movimiento)")
    print("=" * 70)
    matriz_estatica = dc + ruido_blanco
    print(f"Varianza promedio SIN filtrar: {np.mean(np.var(matriz_estatica, axis=0)):.4f}")

    resultado_1 = detector.procesar_ventana(matriz_estatica)
    print(f"Varianza promedio filtrada:    {resultado_1['varianza_promedio']:.4f}")
    print(f"¿Movimiento detectado?:        {resultado_1['movimiento_detectado']}")
    print(
        "(Nota: el filtro pasabanda elimina el DC=100 y la mayor parte del "
        "ruido, dejando una varianza filtrada mucho menor a la varianza "
        "cruda de la señal sin procesar).\n"
    )

    print("=" * 70)
    print("ESCENARIO 2: Movimiento humano simulado (~1.2 Hz)")
    print("=" * 70)
    amplitud_movimiento = 15.0
    frecuencia_movimiento_hz = 1.2  # dentro de la banda de paso del filtro
    señal_movimiento = amplitud_movimiento * np.sin(2 * np.pi * frecuencia_movimiento_hz * t)
    matriz_con_movimiento = dc + ruido_blanco + señal_movimiento[:, np.newaxis]

    resultado_2 = detector.procesar_ventana(matriz_con_movimiento)
    print(f"Varianza promedio filtrada: {resultado_2['varianza_promedio']:.4f}")
    print(f"¿Movimiento detectado?:     {resultado_2['movimiento_detectado']}")
    print(f"¿Evento registrado en BD?:  {resultado_2['evento_registrado']}")
    print(
        "(Nota: 'evento_registrado' depende de que csi_db esté disponible y "
        f"exista un usuario con id={USUARIO_ID_DEMO}; si no, la inserción "
        "falla de forma controlada y queda registrada en el log de errores).\n"
    )

    print("=" * 70)
    print("ESCENARIO 3: Misma ventana de movimiento repetida (sin flanco)")
    print("=" * 70)
    resultado_3 = detector.procesar_ventana(matriz_con_movimiento)
    print(f"¿Movimiento detectado?:     {resultado_3['movimiento_detectado']}")
    print(f"¿Evento registrado en BD?:  {resultado_3['evento_registrado']}")
    print(
        "(Nota: aunque sigue habiendo movimiento, NO se registra un nuevo "
        "evento porque no hubo flanco ascendente: la ventana anterior ya "
        "estaba en estado 'movimiento detectado').\n"
    )
