"""Utilidades puras para inspeccionar y construir paquetes (sin estado, sin conexión al switch).

Hito: M2 (ARP) y M4 (transporte)
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp 

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
    # Caso de fragmento IP no inicial
    if ip_pkt.frag != 0:
        return None
    payload = ip_pkt.payload
    if isinstance(payload, (tcp, udp)) and payload.parsed:
        proto = ipv4.TCP_PROTOCOL if isinstance(payload, tcp) else ipv4.UDP_PROTOCOL
        return TransportInfo(proto, payload.srcport, payload.dstport)
    # Caso otro: ICMP
    return None



def build_arp_request(src_mac: EthAddr, src_ip: IPAddr, target_ip: IPAddr) -> ethernet:
    """
    Arma una trama Ethernet (dst ff:ff:ff:ff:ff:ff, type ARP) con un ARP Request
    "who-has target_ip tell src_ip". `src_mac`/`src_ip` son los de la interfaz del router
    por la que se va a enviar (pública o privada).
    """
    # Arma ARP Req hacia broadcast para consultar la MAC de target_ip
    arp_pack = arp()
    arp_pack.opcode = arp.REQUEST
    arp_pack.hwsrc = src_mac          # (la MAC del router que pregunta).
    arp_pack.protosrc = src_ip        # (la IP del router que pregunta).
    arp_pack.protodst = target_ip     # (la IP que queremos averiguar).
    arp_pack.hwdst = ETHER_BROADCAST  # (no sabemos la MAC destino, así que se pone broadcast ff:ff:ff:ff:ff:ff).

    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.src = src_mac
    eth.dst = ETHER_BROADCAST # (broadcast para que le llegue a todos).
    eth.payload = arp_pack
    return eth


def build_arp_reply(my_mac: EthAddr, my_ip: IPAddr,
                    requester_mac: EthAddr, requester_ip: IPAddr) -> ethernet:
    """
    Arma una trama Ethernet con un ARP Reply "my_ip is-at my_mac", dirigido
    (unicast) a `requester_mac` / `requester_ip`.
    """
    # Arma el ARP Reply, el origen es lo que se buscaba en el req
    arp_pack = arp()
    arp_pack.opcode = arp.REPLY
    arp_pack.hwsrc = my_mac           # (la MAC del host que se consultaba).
    arp_pack.protosrc = my_ip
    arp_pack.protodst = requester_ip
    arp_pack.hwdst = requester_mac    # respondemos el unicast al originante del req

    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.src = my_mac
    eth.dst = requester_mac # unicast al originante
    eth.payload = arp_pack
    return eth
