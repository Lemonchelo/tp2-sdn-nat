"""Utilidades puras para inspeccionar y construir paquetes (sin estado, sin conexión al switch).

Hito: M2 (ARP) y M4 (transporte)
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4


class TransportInfo(NamedTuple):
    """Datos de capa 4 necesarios para identificar una conexión."""
    proto: int       # 6 = TCP, 17 = UDP (ver config.PROTO_*)
    src_port: int
    dst_port: int


def extract_transport(ip_pkt: ipv4) -> Optional[TransportInfo]:
    """Extrae (proto, src_port, dst_port) de un paquete IPv4.

    Qué implementar:
      - Si ip_pkt.payload es TCP o UDP (pox.lib.packet.tcp / udp) devolver TransportInfo.
      - Para cualquier otro protocolo (ICMP incluido) devolver None; el caller decide qué hacer.
      - Devolver None también si el paquete es un fragmento IP no inicial (no hay cabecera L4)
        o si el payload no se pudo parsear.

    Hito: M4
    """
    raise NotImplementedError("TODO(M4): extract_transport")


def build_arp_request(src_mac: EthAddr, src_ip: IPAddr, target_ip: IPAddr) -> ethernet:
    """Arma una trama Ethernet (dst ff:ff:ff:ff:ff:ff, type ARP) con un ARP Request
    "who-has target_ip tell src_ip". `src_mac`/`src_ip` son los de la interfaz del router
    por la que se va a enviar (pública o privada).

    Hito: M2
    """
    raise NotImplementedError("TODO(M2): build_arp_request")


def build_arp_reply(my_mac: EthAddr, my_ip: IPAddr,
                    requester_mac: EthAddr, requester_ip: IPAddr) -> ethernet:
    """Arma una trama Ethernet con un ARP Reply "my_ip is-at my_mac", dirigido
    (unicast) a `requester_mac` / `requester_ip`.

    Hito: M2
    """
    raise NotImplementedError("TODO(M2): build_arp_reply")
