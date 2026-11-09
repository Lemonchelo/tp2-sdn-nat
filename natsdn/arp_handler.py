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
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of

from natsdn.arp_table import ArpTable
from natsdn.config import NatConfig
from natsdn.switch_io import SwitchIO
from natsdn.log_utils import *
from natsdn import packet_utils

from dataclasses import dataclass, field
from pox.lib.recoco import Timer # ver si sirve o si hacemos un "mock" para los test

# callback(mac, switch_port) que se invoca cuando la IP queda resuelta
OnResolved = Callable[[EthAddr, int], None]
# callback() que se invoca si se agotan los reintentos sin respuesta
OnFailed = Callable[[], None]


@dataclass
class _PendingResolution:
    callbacks: list[tuple[OnResolved, Optional[OnFailed]]] = field(default_factory=list)
    retries: int = 0
    out_port: int = 0
    timer: Optional[Timer] = None

class ArpHandler:
    def __init__(self, cfg: NatConfig, table: ArpTable, io: SwitchIO):
        self.cfg = cfg
        self.table = table
        self.io = io
        self._pending: dict[IPAddr, _PendingResolution] = {}

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
        arp_packet = packet.find("arp")
        if arp_packet is None or arp_packet.prototype != arp.PROTO_TYPE_IP:
            return # solo procesa paquetes arp y en ipv4
        
        # 1. aprender 
        if arp_packet.protosrc != IPAddr("0.0.0.0"):
            self.table.learn(arp_packet.protosrc, arp_packet.hwsrc, in_port)

        # 2. Si había alguien esperando esta resolución, completar pendientes
        if arp_packet.protosrc in self._pending:
            self._complete_pending(arp_packet.protosrc)
        
        # 3. Si es request para interfaz del router responder
        if arp_packet.opcode == arp.REQUEST:
            # Valida si preguntan por el router
            if self.cfg.is_router_ip(arp_packet.protodst):
                # Validar coherencia de interfaz
                if in_port == self.cfg.public.port and arp_packet.protodst == self.cfg.public.ip:
                    self.send_arp_reply(packet, in_port)
                elif in_port != self.cfg.public.port and arp_packet.protodst == self.cfg.private.ip:
                    self.send_arp_reply(packet, in_port)
                else:
                    log.debug(f"ARP Request por IP {arp_packet.protodst} llegó por puerto inconsistente {in_port}")
            else:
                log.debug(f"ARP Request ignorado para IP no-router: {arp_packet.protodst}")
                    

    def send_arp_reply(self, request: ethernet, in_port: int) -> None:
        """
        Responde un ARP Request dirigido al router.
        """
        arp_packet = request.find("arp")
        my_mac = self.cfg.private.mac
        my_ip = self.cfg.private.ip
        if in_port == self.cfg.public.port:
            my_mac = self.cfg.public.mac
            my_ip = self.cfg.public.ip
        reply = packet_utils.build_arp_reply(my_mac, my_ip, arp_packet.hwsrc, arp_packet.protosrc)
        self.io.send_packet(reply.pack(), [of.ofp_action_output(port=in_port)])

    def send_arp_request(self, target_ip: IPAddr, out_port: int) -> None:
        """Emite un ARP Request por `out_port` preguntando por `target_ip`.

        Qué implementar: usar como origen la interfaz del router que corresponde al lado de
        `target_ip` (MAC/IP pública si out_port es el puerto público; privada en caso contrario).
        Para un host privado cuyo puerto se desconoce, el puerto de salida debe ser
        of.OFPP_FLOOD (restringido a puertos privados si fuera posible).
        Hito: M2
        """
        src_mac = self.cfg.private.mac
        src_ip = self.cfg.private.ip
        if out_port == self.cfg.public.port:
            src_mac = self.cfg.public.mac
            src_ip = self.cfg.public.ip

        # Si se solicita FLOOD, emitimos por cada puerto privado físico para no filtrar a la red pública
        actions = []
        if out_port == of.OFPP_FLOOD:
            private_ports = [p for p in self.io.physical_ports if p != self.cfg.public.port] # tenemos un solo puerto publico
            if private_ports:
                actions = [of.ofp_action_output(port=p) for p in private_ports]
            else:
                actions = [of.ofp_action_output(port=of.OFPP_FLOOD)]
        else:
            actions = [of.ofp_action_output(port=out_port)]

        req = packet_utils.build_arp_request(src_mac, src_ip, target_ip)
        self.io.send_packet(req.pack(), actions)

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
        arp_entry = self.table.lookup(ip)
        if arp_entry: # si ya esta resuelta llamamos a on_resolved y listo..
            on_resolved(arp_entry.mac, arp_entry.port)
            return
        # hay que resolver la mac buscandola y generando entrada en la arp_table
        if ip in self._pending:
            # al estar pendiente de resolucion solo agregamos el callback en lista
            self._pending[ip].callbacks.append((on_resolved, on_failed))
        else:
            # nueva, la guardamos en pendiente y enviamos el pedido de arp
            pending = _PendingResolution(callbacks=[(on_resolved, on_failed)], out_port=out_port, retries=0)
            pending.timer = Timer(self.cfg.arp_request_timeout, self._on_timeout, args=[ip])
            self._pending[ip] = pending
            self.send_arp_request(ip, out_port)


    def _complete_pending(self, ip: IPAddr) -> None:
        """Si había resolución pendiente para `ip`: cancelar su timer, tomar (mac, port) de la tabla
        ARP, invocar todos los on_resolved encolados y limpiar el pendiente. Hito: M2"""
        if ip not in self._pending:
            log_color(YELLOW, f"_complete_pending de [{ip}] sin estar en lista pendiente")
            return
        # borramos de pendiente
        pending = self._pending.pop(ip)
        if pending.timer is not None:
            pending.timer.cancel()

        arp_entry = self.table.lookup(ip)
        if arp_entry: # si ya esta resuelta llamamos a on_resolved y listo..
            for on_resolved, _ in pending.callbacks:
                on_resolved(arp_entry.mac, arp_entry.port)
        else:
            # no esta en la tabla, capaz expiro
            log_color(YELLOW, f"_complete_pending sin resolucion en arp_table [{ip}]")
            for _, on_failed in pending.callbacks:
                if on_failed is not None:
                    on_failed()

    def _on_timeout(self, ip: IPAddr) -> None:
        """Callback del timer: reintentar o fallar la resolución de `ip` (ver resolve()). Hito: M2"""
        if ip not in self._pending:
            log_color(RED, f"Error _on_timeout ip[{ip}] no pendiente..")
            return
        pending = self._pending[ip]
        pending.retries += 1
        if pending.retries < self.cfg.arp_max_retries:
            # seteamos nuevo timer y reenviamos request
            pending.timer = Timer(self.cfg.arp_request_timeout, self._on_timeout, args=[ip])
            self.send_arp_request(ip, pending.out_port)
        else:
            # limite alcanzado..
            log_color(YELLOW, f"Limite reintento arp alcanzado [{ip}]-[{pending.out_port}]")
            del self._pending[ip]
            for _, on_failed in pending.callbacks:
                if on_failed is not None:
                    on_failed()

