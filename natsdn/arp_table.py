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

from natsdn.log_utils import *

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
        """
        Inserta o refresca la entrada de `ip`.
        Si la IP existe con otra MAC o puerto se actualiza la entrada.
        """
        if ip in self._entries and (self._entries[ip].mac != mac or \
           self._entries[ip].port != port):
            log_color(YELLOW, f"IP=[{ip}] registrada con mac=[\
                      {self._entries[ip].mac}] port=[{self._entries[ip].port}] \
                      - se actualiza con mac=[{mac}] port=[{port}]")
        self._entries[ip] = ArpEntry(ip=ip, mac=mac, port=port, learned_at=self.clock())

    def lookup(self, ip: IPAddr) -> Optional[ArpEntry]:
        """
        Devuelve la entrada vigente de `ip` o None.
        Borra la entrada si existiera pero superó el TTL y devuelve None
        """
        if not ip in self._entries:
            return None
        # existe.. validamos el TTL
        if (self.clock() - self._entries[ip].learned_at) >= self.ttl:
            # expiro borramos la entrada
            del self._entries[ip]
            return None
        return self._entries[ip]

    def expire(self) -> int:
        """
        Elimina todas las entradas vencidas y devuelve cuántas borró (para logging).
        """
        now = self.clock()
        deleted = 0
        for ip, arp_entry in list(self._entries.items()):
            if (now - arp_entry.learned_at) >= self.ttl:
                del self._entries[ip]
                deleted+=1
        return deleted

    def __len__(self) -> int:
        """Cantidad de entradas almacenadas (vencidas o no, no hace falta limpiar acá)."""
        return len(self._entries)
