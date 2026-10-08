"""Interfaz gráfica del detector de movimiento.

Uso: python -m src.ui.dashboard
"""

import logging
import sys
from pathlib import Path

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
if str(RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(RAIZ_PROYECTO))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from src.ui.app import DashboardApp  # noqa: E402

if __name__ == "__main__":
    DashboardApp().mainloop()
