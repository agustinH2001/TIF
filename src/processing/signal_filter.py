"""Procesamiento de señal y detección de movimiento.

Por ventana: limpieza de amplitudes, pasabanda Butterworth (SOS) de 0.5 a 2.5 Hz,
varianza promedio y decisión con confirmación temporal e histéresis.
"""

import itertools
import logging
from datetime import datetime
from typing import Callable, List, Optional, Tuple

import numpy as np
from scipy.ndimage import median_filter
from scipy.signal import butter, sosfiltfilt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("signal_filter")


# fs de respaldo; en vivo se usa la fs medida en cada ventana
FRECUENCIA_MUESTREO_DEFAULT_HZ = 650.0

# Banda de movimiento humano
FRECUENCIA_CORTE_BAJA_HZ = 0.5
FRECUENCIA_CORTE_ALTA_HZ = 2.5

ORDEN_FILTRO_DEFAULT = 4

# Por debajo de esta fs no se filtra (aliasing y muestreo irregular)
FS_MINIMA_CONFIABLE_HZ = 30.0

# Subportadoras ±1..±26: el bin 0 (DC) y los bins 27..37 no tienen canal útil
SUBPORTADORAS_UTILES_20MHZ = np.r_[1:27, 38:64]

# Amplitud en % de la media del paquete (elimina cambios de ganancia)
NORMALIZAR_POR_PAQUETE = True

# Un paquete es atípico si su desvío supera FACTOR x el típico y DESVIO_MINIMO %
FACTOR_RECHAZO_PAQUETE = 5.0
DESVIO_MINIMO_RECHAZO_PCT = 10.0

# Filtro de Hampel temporal
HAMPEL_VENTANA_MUESTRAS = 7
HAMPEL_N_SIGMAS = 3.0


def rechazar_paquetes_atipicos(
    matriz: np.ndarray,
    factor: float = FACTOR_RECHAZO_PAQUETE,
    desvio_minimo_pct: float = DESVIO_MINIMO_RECHAZO_PCT,
) -> Tuple[np.ndarray, int]:
    """Reemplaza por el perfil mediano los paquetes cuya forma se aparta bruscamente del resto.
    Devuelve (matriz, cantidad_reemplazados).
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
    """Selecciona subportadoras útiles, normaliza por paquete, rechaza atípicos y aplica
    Hampel.
    """
    if matriz_amplitud.size == 0 or matriz_amplitud.ndim != 2:
        return (matriz_amplitud, 0) if devolver_conteo else matriz_amplitud

    matriz = np.asarray(matriz_amplitud, dtype=np.float64)

    if matriz.shape[1] == 64:
        matriz = matriz[:, SUBPORTADORAS_UTILES_20MHZ]

    if normalizar:
        media_por_paquete = matriz.mean(axis=1, keepdims=True)
        media_por_paquete[media_por_paquete <= 0] = 1.0
        matriz = 100.0 * matriz / media_por_paquete

    n_atipicos = 0
    if rechazar_atipicos and normalizar:
        matriz, n_atipicos = rechazar_paquetes_atipicos(matriz)

    if hampel_ventana >= 3 and matriz.shape[0] >= hampel_ventana:
        # mode="mirror": con "nearest" un paquete corrupto en el borde no se detecta
        mediana = median_filter(matriz, size=(hampel_ventana, 1), mode="mirror")
        desvio_abs = np.abs(matriz - mediana)
        mad = median_filter(desvio_abs, size=(hampel_ventana, 1), mode="mirror")
        limite = hampel_n_sigmas * 1.4826 * mad
        atipicos = desvio_abs > np.maximum(limite, 1e-12)
        matriz = np.where(atipicos, mediana, matriz)

    return (matriz, n_atipicos) if devolver_conteo else matriz


# Confirmación e histéresis del trigger
VENTANAS_CONFIRMACION_ENTRADA_DEFAULT = 3
VENTANAS_CONFIRMACION_SALIDA_DEFAULT = 5
FACTOR_HISTERESIS_DEFAULT = 0.7

ESTADO_FILTRO_SOS_OK = "SOS_OK"
ESTADO_FILTRO_VENTANA_VACIA = "CRUDA_VENTANA_VACIA"
ESTADO_FILTRO_FS_INSUFICIENTE = "CRUDA_FS_INSUFICIENTE"
ESTADO_FILTRO_MUESTRAS_INSUFICIENTES = "CRUDA_MUESTRAS_INSUFICIENTES"
ESTADO_FILTRO_ERROR_NUMERICO = "CRUDA_ERROR_NUMERICO"

DESCRIPCION_ESTADO_FILTRO = {
    ESTADO_FILTRO_SOS_OK: "Filtrada (Butterworth SOS)",
    ESTADO_FILTRO_VENTANA_VACIA: "Ventana vacía",
    ESTADO_FILTRO_FS_INSUFICIENTE: "fs real demasiado baja",
    ESTADO_FILTRO_MUESTRAS_INSUFICIENTES: "Muy pocas muestras en la ventana",
    ESTADO_FILTRO_ERROR_NUMERICO: "Salida del filtro no finita",
}


def filtro_fue_aplicado(estado_filtro: str) -> bool:
    """True si el estado indica que la ventana se filtró."""
    return estado_filtro == ESTADO_FILTRO_SOS_OK


def _padlen_minimo_sosfiltfilt(sos: np.ndarray) -> int:
    """Cantidad mínima de muestras que exige sosfiltfilt (mismo cálculo que scipy)."""
    n_taps = 2 * sos.shape[0] + 1
    n_taps -= min(int((sos[:, 2] == 0).sum()), int((sos[:, 5] == 0).sum()))
    return 3 * n_taps


def filtrar_señal_butterworth(
    matriz_amplitud: np.ndarray,
    frecuencia_muestreo: float = FRECUENCIA_MUESTREO_DEFAULT_HZ,
    freq_corte_baja: float = FRECUENCIA_CORTE_BAJA_HZ,
    freq_corte_alta: float = FRECUENCIA_CORTE_ALTA_HZ,
    orden: int = ORDEN_FILTRO_DEFAULT,
    fs_minima: float = FS_MINIMA_CONFIABLE_HZ,
) -> Tuple[np.ndarray, str]:
    """Aplica el pasabanda a cada subportadora. Devuelve (matriz, estado_filtro).

    Si no se puede filtrar (fs baja, pocas muestras, salida inválida) devuelve la matriz sin
    cambios
    y un estado CRUDA_*.
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

    if freq_corte_baja >= freq_corte_alta:
        logger.debug(
            f"Banda de paso vacía para fs={frecuencia_muestreo:.3f} Hz "
            f"(Nyquist={nyquist:.3f} Hz)."
        )
        return matriz_amplitud, ESTADO_FILTRO_FS_INSUFICIENTE

    baja_normalizada = freq_corte_baja / nyquist
    alta_normalizada = freq_corte_alta / nyquist

    # Forma SOS: con (b, a) el filtro es inestable para una banda tan angosta
    sos = butter(orden, [baja_normalizada, alta_normalizada], btype="bandpass", output="sos")

    padlen = _padlen_minimo_sosfiltfilt(sos)
    if n_paquetes <= padlen:
        logger.debug(
            f"Ventana de {n_paquetes} paquetes insuficiente para sosfiltfilt "
            f"(orden {orden}): se necesitan más de {padlen}."
        )
        return matriz_amplitud, ESTADO_FILTRO_MUESTRAS_INSUFICIENTES

    try:
        matriz_filtrada = sosfiltfilt(sos, matriz_amplitud, axis=0)
    except ValueError as e:
        logger.debug(f"sosfiltfilt falló sobre {n_paquetes} paquetes: {e}")
        return matriz_amplitud, ESTADO_FILTRO_MUESTRAS_INSUFICIENTES

    if not np.all(np.isfinite(matriz_filtrada)):
        logger.debug("La salida del filtro contiene NaN/Inf.")
        return matriz_amplitud, ESTADO_FILTRO_ERROR_NUMERICO

    return matriz_filtrada, ESTADO_FILTRO_SOS_OK


def calcular_varianza_promedio(matriz_filtrada: np.ndarray) -> float:
    """Promedio de las varianzas de cada subportadora en la ventana."""
    if matriz_filtrada.size == 0:
        return 0.0

    varianza_por_subportadora = np.var(matriz_filtrada, axis=0)
    return float(np.mean(varianza_por_subportadora))


def evaluar_trigger_movimiento(varianza_promedio: float, umbral: float) -> Tuple[bool, float]:
    """Devuelve (varianza > umbral, varianza)."""
    movimiento_detectado = varianza_promedio > umbral
    return movimiento_detectado, varianza_promedio


class DetectorMovimiento:
    """Detector con estado: procesa ventanas y maneja el ciclo de vida de los eventos.

    Reposo -> movimiento: N ventanas seguidas sobre el umbral (se abre el evento).
    Movimiento -> reposo: M ventanas seguidas bajo umbral * factor_histeresis (se cierra el
    evento).

    Al abrir y cerrar un evento se avisa a cada acción de `acciones` con
    al_iniciar(id_evento, inicio, varianza) y
    al_finalizar(id_evento, inicio, fin, duracion, varianza_maxima).
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
        acciones: Optional[List] = None,
        reloj: Callable[[], datetime] = datetime.now,
    ) -> None:
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

        self._en_movimiento: bool = False
        self._racha_sobre_umbral: int = 0
        self._racha_bajo_umbral_salida: int = 0
        self._varianza_maxima_racha: float = 0.0
        self._ultimo_n_atipicos: int = 0

        self.acciones = list(acciones or [])
        self._reloj = reloj
        self._ids_evento = itertools.count(1)
        self._id_evento: Optional[int] = None
        self._inicio_racha: Optional[datetime] = None
        self._inicio_racha_salida: Optional[datetime] = None
        self._inicio_evento: Optional[datetime] = None
        self._varianza_maxima_evento: float = 0.0

    @property
    def umbral_salida(self) -> float:
        """Umbral para volver a reposo (umbral * factor_histeresis)."""
        return float(self.umbral_sensibilidad) * self.factor_histeresis

    def procesar_ventana(
        self, matriz_amplitud: np.ndarray, frecuencia_muestreo: Optional[float] = None
    ) -> dict:
        """Procesa una ventana de amplitudes y devuelve un dict con el resultado."""
        fs_efectiva = (
            frecuencia_muestreo if frecuencia_muestreo is not None else self.frecuencia_muestreo
        )
        n_paquetes = int(matriz_amplitud.shape[0]) if matriz_amplitud.ndim > 0 else 0

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

        # Ventana no filtrada: no se compara con el umbral ni se cambia el estado
        if not filtro_aplicado:
            return self._armar_resultado(
                varianza_promedio, fs_efectiva, filtro_aplicado, estado_filtro,
                n_paquetes, supera_umbral=False, evento_registrado=False,
            )

        supera_umbral, varianza_promedio = evaluar_trigger_movimiento(
            varianza_promedio, self.umbral_sensibilidad
        )
        evento_registrado = False

        if not self._en_movimiento:
            if supera_umbral:
                if self._racha_sobre_umbral == 0:
                    self._inicio_racha = self._reloj()
                self._racha_sobre_umbral += 1
                self._varianza_maxima_racha = max(self._varianza_maxima_racha, varianza_promedio)
            else:
                if self._racha_sobre_umbral > 0:
                    logger.info(
                        f"Pico descartado: {self._racha_sobre_umbral} ventana(s) sobre el "
                        f"umbral (máx {self._varianza_maxima_racha:.3f}), se necesitaban "
                        f"{self.ventanas_confirmacion_entrada} para confirmar."
                    )
                self._racha_sobre_umbral = 0
                self._varianza_maxima_racha = 0.0
                self._inicio_racha = None

            if self._racha_sobre_umbral >= self.ventanas_confirmacion_entrada:
                self._en_movimiento = True
                self._racha_bajo_umbral_salida = 0
                self._inicio_racha_salida = None
                evento_registrado = self._iniciar_evento()
        else:
            self._varianza_maxima_evento = max(self._varianza_maxima_evento, varianza_promedio)
            self._racha_sobre_umbral = self._racha_sobre_umbral + 1 if supera_umbral else 0
            if varianza_promedio < self.umbral_salida:
                if self._racha_bajo_umbral_salida == 0:
                    self._inicio_racha_salida = self._reloj()
                self._racha_bajo_umbral_salida += 1
            else:
                self._racha_bajo_umbral_salida = 0
                self._inicio_racha_salida = None

            if self._racha_bajo_umbral_salida >= self.ventanas_confirmacion_salida:
                self._finalizar_evento(self._inicio_racha_salida or self._reloj())

        return self._armar_resultado(
            varianza_promedio, fs_efectiva, filtro_aplicado, estado_filtro,
            n_paquetes, supera_umbral=supera_umbral, evento_registrado=evento_registrado,
        )

    def _iniciar_evento(self) -> bool:
        """Abre un evento y avisa a las acciones."""
        self._inicio_evento = self._inicio_racha or self._reloj()
        self._varianza_maxima_evento = self._varianza_maxima_racha
        self._id_evento = next(self._ids_evento)

        logger.info(
            f"Movimiento CONFIRMADO (usuario {self.usuario_id}) tras "
            f"{self.ventanas_confirmacion_entrada} ventanas seguidas sobre el umbral: "
            f"inicio={self._inicio_evento:%H:%M:%S}, "
            f"varianza_max={self._varianza_maxima_evento:.4f}."
        )
        self._avisar_acciones(
            "al_iniciar", self._id_evento, self._inicio_evento, self._varianza_maxima_evento
        )
        return True

    def _finalizar_evento(self, timestamp_fin: datetime) -> None:
        """Cierra el evento en curso y vuelve a reposo."""
        inicio = self._inicio_evento or timestamp_fin
        duracion = max((timestamp_fin - inicio).total_seconds(), 0.0)

        logger.info(
            f"Fin de movimiento (usuario {self.usuario_id}): duración≈{duracion:.1f}s, "
            f"varianza_max={self._varianza_maxima_evento:.4f}."
        )
        self._avisar_acciones(
            "al_finalizar", self._id_evento, inicio, timestamp_fin, duracion,
            self._varianza_maxima_evento,
        )
        self.reiniciar_estado()

    def _avisar_acciones(self, metodo: str, *args) -> None:
        """Llama a `metodo` en cada acción; un error en una acción no frena la detección."""
        for accion in self.acciones:
            try:
                getattr(accion, metodo)(*args)
            except Exception as e:
                logger.error(f"Error en la acción {type(accion).__name__}.{metodo}: {e}")

    def forzar_fin_evento(self) -> None:
        """Cierra el evento en curso, si hay uno (por ejemplo, al cortarse el stream)."""
        if self._en_movimiento:
            logger.info("Se cierra el evento de movimiento en curso por fin del stream.")
            self._finalizar_evento(self._reloj())
        else:
            self.reiniciar_estado()

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

    def reiniciar_estado(self) -> None:
        """Vuelve a reposo sin registrar nada."""
        self._en_movimiento = False
        self._racha_sobre_umbral = 0
        self._racha_bajo_umbral_salida = 0
        self._varianza_maxima_racha = 0.0
        self._inicio_racha = None
        self._inicio_racha_salida = None
        self._inicio_evento = None
        self._varianza_maxima_evento = 0.0
        self._id_evento = None


if __name__ == "__main__":
    FS_SIMULADA = 140.0
    N_SUBPORTADORAS = 64
    DURACION_VENTANA_SEG = 2
    UMBRAL_DEMO = 2.0

    n = int(FS_SIMULADA * DURACION_VENTANA_SEG)
    t = np.arange(n) / FS_SIMULADA
    rng = np.random.default_rng(seed=42)

    perfil = 400.0 + 150.0 * np.cos(np.linspace(0, 2 * np.pi, N_SUBPORTADORAS))
    patron_espacial = np.sin(np.linspace(0, 6 * np.pi, N_SUBPORTADORAS))

    def ventana(intensidad_movimiento: float) -> np.ndarray:
        m = perfil * (1 + 0.01 * rng.normal(size=(n, N_SUBPORTADORAS)))
        m *= rng.choice([1.0, 1.0, 1.0, 1.35, 0.8], size=(n, 1))
        m[:, [0, 28, 29, 30, 31, 32, 33, 34, 35]] = rng.uniform(0, 35000, size=(n, 9))
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
