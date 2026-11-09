"""Tabla de traducción NAT/PAT (lógica pura, sin conexión al switch).

Diseño de la tabla (ver docs/ARQUITECTURA.md §4):
  - Un NatEntry por CONEXIÓN (5-tupla saliente), no por host. Así cada entry corresponde a un
    par de flujos OpenFlow (saliente + entrante) y se puede liberar de forma independiente.
  - Dos índices sobre el mismo objeto:
        saliente: (proto, priv_ip, priv_port, remote_ip, remote_port) -> NatEntry
        entrante: (proto, public_port)                                 -> NatEntry
  - El puerto público es único por protocolo (lo garantiza PortPool).
  - Ciclo de vida: el entry se libera cuando los DOS flujos fueron removidos del switch
    (FlowRemoved por idle_timeout), o por expire_stale() como red de seguridad.

Hito: M3
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from pox.lib.addresses import IPAddr

from natsdn.port_pool import PortPool


class Direction(enum.IntEnum):
    OUTBOUND = 0   # privada -> pública
    INBOUND = 1    # pública -> privada


@dataclass
class NatEntry:
    entry_id: int            # único; se usa para armar el cookie de los flujos
    proto: int               # 6 TCP / 17 UDP
    priv_ip: IPAddr
    priv_port: int           # puerto L4 origen del host privado
    priv_switch_port: int    # puerto del SWITCH por donde está el host privado
    remote_ip: IPAddr
    remote_port: int
    public_port: int         # puerto L4 asignado por el PAT
    created_at: float
    last_seen: float
    # Qué flujos siguen instalados en el switch
    flow_active: dict[Direction, bool] = field(
        default_factory=lambda: {Direction.OUTBOUND: False, Direction.INBOUND: False})


class NatTable:
    def __init__(self, port_pool: PortPool, clock: Callable[[], float] = time.monotonic):
        self.port_pool = port_pool
        self.clock = clock
        self._next_id = 1
        self._by_outbound: dict[tuple, NatEntry] = {}
        self._by_inbound: dict[tuple, NatEntry] = {}

    def get_or_create_outbound(self, proto: int, priv_ip: IPAddr, priv_port: int,
                               priv_switch_port: int, remote_ip: IPAddr,
                               remote_port: int) -> Optional[NatEntry]:
        """Devuelve el NatEntry de esta conexión saliente; lo crea si no existe.

        Qué implementar:
          - Buscar por la clave saliente; si existe, actualizar last_seen y devolverlo
            (idempotente: llamarla dos veces con la misma 5-tupla NO consume otro puerto).
          - Si no existe: pedir puerto a PortPool.allocate(proto, preferred=priv_port),
            crear el NatEntry con un entry_id nuevo, indexarlo en ambos diccionarios.
          - Si el pool está agotado devolver None (el caller dropea y loguea).

        Hito: M3
        """
        key = (proto, priv_ip, priv_port, remote_ip, remote_port)
        entry = self._by_outbound.get(key)
        if entry is not None:
            entry.last_seen = self.clock()
            return entry
        public_port = self.port_pool.allocate(proto, preferred=priv_port)
        if public_port is None:
            return None
        now = self.clock()
        entry = NatEntry(self._next_id, proto, priv_ip, priv_port, priv_switch_port,
                         remote_ip, remote_port, public_port, now, now)
        self._next_id += 1
        self._by_outbound[key] = entry
        self._by_inbound[(proto, public_port)] = entry
        return entry

    def lookup_inbound(self, proto: int, public_port: int) -> Optional[NatEntry]:
        """Busca el entry correspondiente a un paquete que llega de la red pública
        (dst_port == public_port). None si no hay mapeo (tráfico no solicitado -> drop).
        Hito: M3"""
        return self._by_inbound.get((proto, public_port))

    def get_by_id(self, entry_id: int) -> Optional[NatEntry]:
        """Búsqueda por entry_id (lo usa el handler de FlowRemoved vía el cookie). Hito: M3"""
        return next((entry for entry in self._by_outbound.values()
                     if entry.entry_id == entry_id), None)

    def mark_flow_installed(self, entry: NatEntry, direction: Direction) -> None:
        """Registra que el flujo `direction` de `entry` quedó instalado en el switch
        y refresca last_seen. Hito: M3"""
        entry.flow_active[direction] = True
        entry.last_seen = self.clock()

    def on_flow_removed(self, entry: NatEntry, direction: Direction) -> bool:
        """Registra que el switch removió el flujo `direction` (timeout o delete).

        Qué implementar: marcar flow_active[direction] = False; si AMBAS direcciones quedaron
        inactivas, liberar el entry (release) y devolver True; si no, devolver False.

        Por qué no liberar apenas expira un sentido: en tráfico unidireccional (ej. UDP que solo
        envía el cliente) el flujo entrante envejece pero la conexión sigue viva.
        Hito: M3
        """
        entry.flow_active[direction] = False
        if any(entry.flow_active.values()):
            return False
        self.release(entry)
        return True

    def release(self, entry: NatEntry) -> None:
        """Quita el entry de ambos índices y devuelve su puerto público a PortPool. Hito: M3"""
        key = (entry.proto, entry.priv_ip, entry.priv_port, entry.remote_ip, entry.remote_port)
        # Un callback tardío de un entry liberado no debe borrar su reemplazo.
        if self._by_outbound.get(key) is not entry:
            return
        del self._by_outbound[key]
        del self._by_inbound[(entry.proto, entry.public_port)]
        self.port_pool.release(entry.proto, entry.public_port)

    def expire_stale(self, max_age: float) -> list[NatEntry]:
        """Red de seguridad por si se perdió algún FlowRemoved: libera y devuelve los entries
        con (clock() - last_seen) > max_age. Se invoca periódicamente desde NatRouter. Hito: M3"""
        now = self.clock()
        expired = [entry for entry in self._by_outbound.values()
                   if now - entry.last_seen > max_age]
        for entry in expired:
            self.release(entry)
        return expired

    def entries(self) -> Iterator[NatEntry]:
        """Itera los entries vivos (para el comando de debug/dump de la tabla). Hito: M3"""
        return iter(self._by_outbound.values())
