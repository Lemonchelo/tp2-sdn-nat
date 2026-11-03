"""Manejo de ARP: responder por las IPs del router y resolver MACs de hosts (privados y público).

Dos responsabilidades:
  1. PROXY/RESPONDER: ARP Request cuya IP destino es una IP del router -> ARP Reply con la MAC
     de la interfaz correspondiente (pública o privada). Es lo que permite sacar el setARP()
     estático de topo.py.
  2. RESOLVER: cuando el NAT necesita la MAC de un destino (servidor público al salir, host
     privado al entrar y no hay entrada vigente) se genera un ARP Request y los paquetes que
     esperan quedan en una cola pendiente hasta que llegue el Reply (o se agoten los reintentos).

Hito: M2
"""

from __future__ import annotations

from typing import Callable, Optional

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet

from natsdn.arp_table import ArpTable
from natsdn.config import NatConfig
from natsdn.switch_io import SwitchIO

# callback(mac, switch_port) que se invoca cuando la IP queda resuelta
OnResolved = Callable[[EthAddr, int], None]
# callback() que se invoca si se agotan los reintentos sin respuesta
OnFailed = Callable[[], None]


class ArpHandler:
    def __init__(self, cfg: NatConfig, table: ArpTable, io: SwitchIO):
        self.cfg = cfg
        self.table = table
        self.io = io
        # ip pendiente -> estado de la resolución (callbacks en espera, reintentos, timer).
        # Estructura exacta a criterio de quien implemente; ver resolve().
        self._pending: dict[IPAddr, object] = {}

    def handle_arp(self, packet: ethernet, in_port: int) -> None:
        """Procesa un paquete ARP que llegó al controlador.

        Qué implementar:
          1. Aprender SIEMPRE (protosrc -> hwsrc, in_port) en la tabla ARP, sea request o reply
             (ignorar protosrc 0.0.0.0, que es un ARP probe).
          2. Si es REQUEST y protodst es una IP del router (cfg.is_router_ip) -> send_arp_reply().
             Validar que la IP pedida corresponda a la interfaz del lado por el que llegó
             (in_port == cfg.public.port <-> IP pública; resto <-> IP privada).
          3. Si es REPLY (o cualquier ARP que resuelva una IP pendiente) -> completar la
             resolución: _complete_pending(ip).
          4. Cualquier otro ARP (request por IPs que no son del router): ignorar y loguear en
             DEBUG. (No se hace flooding: la comunicación entre hosts privados está fuera
             de alcance, ver docs/ARQUITECTURA.md §8.)

        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpHandler.handle_arp")

    def send_arp_reply(self, request: ethernet, in_port: int) -> None:
        """Responde un ARP Request dirigido al router.

        Qué implementar: elegir (mac, ip) de la interfaz según el lado, construir la respuesta con
        packet_utils.build_arp_reply() y enviarla por `in_port` con io.send_packet().
        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpHandler.send_arp_reply")

    def send_arp_request(self, target_ip: IPAddr, out_port: int) -> None:
        """Emite un ARP Request por `out_port` preguntando por `target_ip`.

        Qué implementar: usar como origen la interfaz del router que corresponde al lado de
        `target_ip` (MAC/IP pública si out_port es el puerto público; privada en caso contrario).
        Para un host privado cuyo puerto se desconoce, el puerto de salida debe ser
        of.OFPP_FLOOD (restringido a puertos privados si fuera posible).
        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpHandler.send_arp_request")

    def resolve(self, ip: IPAddr, out_port: int, on_resolved: OnResolved,
                on_failed: Optional[OnFailed] = None) -> None:
        """API que usa el NAT: 'necesito la MAC de `ip`'.

        Qué implementar:
          - Si la tabla ARP tiene entrada vigente: llamar on_resolved(mac, port) YA.
          - Si no: encolar (on_resolved, on_failed) en self._pending[ip]. Si es la primera
            espera por esa IP, enviar send_arp_request() y armar un timer
            (cfg.arp_request_timeout) que reintente hasta cfg.arp_max_retries veces.
            Si ya había una resolución en curso, solo encolar (NO duplicar requests).
          - Al agotar reintentos: llamar a todos los on_failed (el NAT descarta los paquetes y
            loguea) y limpiar el pendiente.
        Hito: M2
        """
        raise NotImplementedError("TODO(M2): ArpHandler.resolve")

    def _complete_pending(self, ip: IPAddr) -> None:
        """Si había resolución pendiente para `ip`: cancelar su timer, tomar (mac, port) de la tabla
        ARP, invocar todos los on_resolved encolados y limpiar el pendiente. Hito: M2"""
        raise NotImplementedError("TODO(M2): ArpHandler._complete_pending")

    def _on_timeout(self, ip: IPAddr) -> None:
        """Callback del timer: reintentar o fallar la resolución de `ip` (ver resolve()). Hito: M2"""
        raise NotImplementedError("TODO(M2): ArpHandler._on_timeout")
