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
        raise NotImplementedError("TODO(M2): SwitchIO.send_packet")

    def install_flow(self, match: of.ofp_match, actions: Sequence, idle_timeout: int,
                     priority: int, cookie: int = 0, send_flow_removed: bool = True,
                     hard_timeout: int = 0) -> None:
        """Envía un ofp_flow_mod (OFPFC_ADD).

        Qué implementar: copiar los parámetros al flow_mod; si send_flow_removed, activar el flag
        of.OFPFF_SEND_FLOW_REM (sin esto el controlador nunca se entera de las expiraciones).
        Hito: M4
        """
        raise NotImplementedError("TODO(M4): SwitchIO.install_flow")

    def delete_flow(self, match: of.ofp_match, priority: Optional[int] = None) -> None:
        """Envía un ofp_flow_mod de borrado ESTRICTO (OFPFC_DELETE_STRICT) con ese match.

        Ojo: en OpenFlow 1.0 NO se puede borrar por cookie (eso aparece en OF 1.1+), por eso
        remove_flows() del FlowInstaller debe reconstruir los matches exactos.
        Hito: M4
        """
        raise NotImplementedError("TODO(M4): SwitchIO.delete_flow")
