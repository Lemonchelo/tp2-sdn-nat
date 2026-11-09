"""Pool de puertos públicos del PAT (lógica pura).

Decisión de diseño: el espacio de puertos es independiente por protocolo (TCP y UDP no
colisionan entre sí), y un puerto público identifica UNA conexión dentro de su protocolo.

Hito: M3
"""

from __future__ import annotations

import logging
from typing import Optional


log = logging.getLogger(__name__)


class PortPool:
    def __init__(self, port_min: int, port_max: int):
        """Pool inclusivo [port_min, port_max] por protocolo."""
        self.port_min = port_min
        self.port_max = port_max
        self._in_use: dict[int, set[int]] = {}   # proto -> puertos ocupados
        self._next: dict[int, int] = {}          # proto -> próximo candidato (barrido circular)

    def allocate(self, proto: int, preferred: Optional[int] = None) -> Optional[int]:
        """Reserva y devuelve un puerto público libre para `proto`, o None si el pool está agotado.

        Qué implementar:
          - Si `preferred` está dentro del rango y libre, devolverlo (preservar el puerto
            origen privado cuando se pueda, como hacen los NAT reales).
          - Si no, barrer circularmente desde self._next[proto] hasta encontrar uno libre
            (evita reutilizar de inmediato un puerto recién liberado).
          - Marcarlo como ocupado antes de devolverlo. Si no hay ninguno libre, devolver None.

        Hito: M3
        """
        used = self._in_use.setdefault(proto, set())
        if preferred is not None and self.port_min <= preferred <= self.port_max and preferred not in used:
            port = preferred
        else:
            size = self.port_max - self.port_min + 1
            if len(used) >= size:
                return None
            start = self._next.get(proto, self.port_min)
            for offset in range(size):
                port = self.port_min + (start - self.port_min + offset) % size
                if port not in used:
                    break
            else:
                return None
        used.add(port)
        self._next[proto] = self.port_min if port == self.port_max else port + 1
        return port

    def release(self, proto: int, port: int) -> None:
        """Libera `port` de `proto`. Liberar un puerto que no estaba ocupado no debe romper
        (loguear warning). Hito: M3"""
        used = self._in_use.get(proto)
        if used is None or port not in used:
            log.warning("Liberación de puerto no reservado: proto=%s port=%s", proto, port)
            return
        used.remove(port)

    def in_use(self, proto: int, port: int) -> bool:
        """True si el puerto está reservado. Hito: M3"""
        return port in self._in_use.get(proto, set())

    def available(self, proto: int) -> int:
        """Cantidad de puertos libres para `proto` (útil para logs y tests). Hito: M3"""
        return self.port_max - self.port_min + 1 - len(self._in_use.get(proto, set()))
