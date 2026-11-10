"""Capa fina sobre la conexión OpenFlow con el switch.

Existe para que el resto de los módulos no toquen `connection` directamente (y para poder
reemplazarla por un fake en tests). Solo encapsula mensajes OF 1.0; no conoce NAT ni ARP.

Hito: M2/M4
"""

from __future__ import annotations

from typing import Optional, Sequence

import pox.openflow.libopenflow_01 as of


class SwitchIO:
    def __init__(self, connection):
        self.connection = connection

    def send_packet(self, data: bytes, actions: Sequence, in_port: int = of.OFPP_NONE) -> None:
        """Envía un ofp_packet_out con `data` (trama Ethernet cruda) y la lista de `actions`.

        Qué implementar: armar ofp_packet_out(data=data, in_port=in_port, actions=actions)
        y enviarlo por self.connection. Lo usan ARP (request/reply: una sola acción output)
        y el reenvío del primer paquete de una conexión (mismas acciones que el flujo).

        Hito: M2
        """
        msg = of.ofp_packet_out()
        msg.data = data
        msg.in_port = in_port
        msg.actions = list(actions)
        self.connection.send(msg)

    def install_flow(self, match: of.ofp_match, actions: Sequence, idle_timeout: int,
                     priority: int, cookie: int = 0, send_flow_removed: bool = True,
                     hard_timeout: int = 0) -> None:
        """Envía un ofp_flow_mod (OFPFC_ADD).

        Qué implementar: copiar los parámetros al flow_mod; si send_flow_removed, activar el flag
        of.OFPFF_SEND_FLOW_REM (sin esto el controlador nunca se entera de las expiraciones).
        Hito: M4
        """
        msg = of.ofp_flow_mod(command = of.OFPFC_ADD)
        msg.match = match
        msg.actions = actions
        msg.idle_timeout = idle_timeout
        msg.priority = priority
        msg.cookie = cookie

        if send_flow_removed: 
            msg.flags |= of.OFPFF_SEND_FLOW_REM

        msg.hard_timeout = hard_timeout

        self.connection.send(msg)

    def delete_flow(self, match: of.ofp_match, priority: Optional[int] = None) -> None:
        """Envía un ofp_flow_mod de borrado ESTRICTO (OFPFC_DELETE_STRICT) con ese match.

        Ojo: en OpenFlow 1.0 NO se puede borrar por cookie (eso aparece en OF 1.1+), por eso
        remove_flows() del FlowInstaller debe reconstruir los matches exactos.
        Hito: M4
        """
        msg = of.ofp_flow_mod(command = of.OFPFC_DELETE_STRICT)
        msg.match = match
        if priority is not None:
            msg.priority = priority

        self.connection.send(msg)


    @property
    def physical_ports(self) -> list[int]:
        """Devuelve los números de puertos físicos del switch."""
        if not hasattr(self.connection, "ports"):
            return []
        # En OF 1.0, los puertos físicos tienen valores menores o iguales a OFPP_MAX (0xff00 = 65280)
        return [port for port in self.connection.ports if port <= of.OFPP_MAX]

