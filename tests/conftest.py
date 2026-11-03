"""Los tests unitarios cubren SOLO la lógica pura (ArpTable, PortPool, NatTable): no necesitan
Mininet ni un switch, pero sí importar POX (tipos IPAddr/EthAddr).

POX se busca en $POX_DIR (por defecto ./pox, el que deja scripts/setup.sh).
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POX_DIR = os.environ.get("POX_DIR", os.path.join(ROOT, "pox"))
for p in (ROOT, POX_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)


class FakeClock:
    """Reloj controlable para testear expiraciones sin dormir."""

    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    return FakeClock()
