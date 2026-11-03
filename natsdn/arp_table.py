"""Tabla ARP dinámica del router (lógica pura, testeable sin POX corriendo).

Mapea IP -> (MAC, puerto del switch donde se la vio). Guardar el puerto es clave: el router
necesita saber por qué puerto sacar un paquete hacia un host privado concreto.

Hito: M2
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from pox.lib.addresses import EthAddr, IPAddr


@dataclass
class ArpEntry:
    ip: IPAddr
    mac: EthAddr
    port: int            # puerto del switch por el que se aprendió
    learned_at: float    # timestamp (según el reloj inyectado)


class ArpTable:
    def __init__(self, ttl: float, clock: Callable[[], float] = time.monotonic):
        """`ttl`: segundos de vida de una entrada. `clock` se inyecta para poder testear
        expiración sin dormir (en tests se pasa un reloj falso)."""
        self.ttl = ttl
        self.clock = clock
        self._entries: dict[IPAddr, ArpEntry] = {}

    def learn(self, ip: IPAddr, mac: EthAddr, port: int) -> None:
        """Inserta o refresca la entrada de `ip`.

        Qué implementar: guardar/actualizar (mac, port, learned_at=clock()). Si la IP ya
        existía con otra MAC o puerto, sobrescribir (el host pudo cambiar) y loguear el cambio.
        Se llama al ver CUALQUIER ARP (request o reply) y no solo en las respuestas.

        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpTable.learn")

    def lookup(self, ip: IPAddr) -> Optional[ArpEntry]:
        """Devuelve la entrada vigente de `ip` o None.

        Qué implementar: si la entrada existe pero superó el TTL, eliminarla y devolver None.

        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpTable.lookup")

    def expire(self) -> int:
        """Elimina todas las entradas vencidas y devuelve cuántas borró (para logging).

        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpTable.expire")

    def __len__(self) -> int:
        """Cantidad de entradas almacenadas (vencidas o no, no hace falta limpiar acá)."""
        return len(self._entries)
