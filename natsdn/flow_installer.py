"""Traduce un NatEntry a reglas OpenFlow 1.0 (y las desinstala).

Una conexión NAT = DOS flujos exactos (ver docs/ARQUITECTURA.md §5):

  SALIENTE  match:   in_port=<puerto del host privado>, dl_type=0x0800, nw_proto=<proto>,
                     nw_src=priv_ip, tp_src=priv_port, nw_dst=remote_ip, tp_dst=remote_port
            actions: set dl_src=<MAC pública del router>, set dl_dst=<MAC del destino público>,
                     set nw_src=<IP pública>, set tp_src=public_port, output <puerto público>

  ENTRANTE  match:   in_port=<puerto público>, dl_type=0x0800, nw_proto=<proto>,
                     nw_src=remote_ip, tp_src=remote_port, nw_dst=<IP pública>, tp_dst=public_port
            actions: set dl_src=<MAC privada del router>, set dl_dst=<MAC del host privado>,
                     set nw_dst=priv_ip, set tp_dst=priv_port, output <puerto del host privado>

Los flujos llevan idle_timeout (según protocolo), OFPFF_SEND_FLOW_REM y un cookie que
codifica (entry_id, dirección) para identificarlos en el evento FlowRemoved.

Hito: M4
"""

from __future__ import annotations

from typing import Sequence

import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr

from natsdn.config import NatConfig
from natsdn.nat_table import Direction, NatEntry
from natsdn.switch_io import SwitchIO


class FlowInstaller:
    def __init__(self, cfg: NatConfig, io: SwitchIO):
        self.cfg = cfg
        self.io = io

    # ---- cookie <-> (entry_id, direction) ------------------------------------------

    @staticmethod
    def make_cookie(entry_id: int, direction: Direction) -> int:
        """Codifica (entry_id, direction) en un entero de 64 bits. Ej.: (entry_id << 1) | direction.
        Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.make_cookie")

    @staticmethod
    def parse_cookie(cookie: int) -> tuple[int, Direction]:
        """Inversa de make_cookie. Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.parse_cookie")

    # ---- matches y acciones ----------------------------------------------------------

    def build_match(self, entry: NatEntry, direction: Direction) -> of.ofp_match:
        """Arma el ofp_match EXACTO del flujo `direction` de `entry` (ver tabla del docstring
        del módulo). Se usa tanto para instalar como para borrar (delete estricto).
        Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.build_match")

    def build_outbound_actions(self, entry: NatEntry, next_hop_mac: EthAddr) -> Sequence:
        """Lista ORDENADA de acciones del flujo saliente (reescritura de L2, L3, L4 y output).
        La MISMA lista se reutiliza en el packet_out del primer paquete, así el primer paquete
        sale traducido igual que los siguientes sin reescribirlo a mano.
        Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.build_outbound_actions")

    def build_inbound_actions(self, entry: NatEntry, priv_host_mac: EthAddr) -> Sequence:
        """Lista ordenada de acciones del flujo entrante. Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.build_inbound_actions")

    # ---- instalación / borrado -------------------------------------------------------

    def install_outbound(self, entry: NatEntry, next_hop_mac: EthAddr) -> Sequence:
        """Instala el flujo saliente (match + acciones + idle_timeout + cookie + SEND_FLOW_REM)
        y devuelve la lista de acciones usada (para el packet_out del primer paquete).
        Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.install_outbound")

    def install_inbound(self, entry: NatEntry, priv_host_mac: EthAddr) -> Sequence:
        """Instala el flujo entrante y devuelve las acciones usadas. Se instala junto con el
        saliente (para que la respuesta del servidor no pase por el controlador) y también
        cuando el flujo entrante expiró pero el mapeo sigue vivo.
        Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.install_inbound")

    def remove_flows(self, entry: NatEntry) -> None:
        """Borra del switch los flujos (ambas direcciones) de `entry`, con delete estricto
        sobre build_match(). Hito: M4"""
        raise NotImplementedError("TODO(M4): FlowInstaller.remove_flows")
