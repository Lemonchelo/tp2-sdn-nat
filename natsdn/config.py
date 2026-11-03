"""Configuración compartida por el controlador (y por topo.py, que lee el mismo JSON).

Decisión de diseño: NINGÚN valor de red está hardcodeado en el código del controlador.
Todo sale de config/network.json, así en la demo se pueden cambiar IPs/MACs sin tocar código.
El controlador solo conoce la configuración del *router* (interfaces) y los parámetros
del NAT/ARP; jamás las IPs/MACs de los hosts (esas se descubren por ARP).

Hito: M1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pox.lib.addresses import EthAddr, IPAddr

DEFAULT_CONFIG_PATH = "config/network.json"

# Números de protocolo IP que maneja el NAT
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class Interface:
    """Una interfaz lógica del router (el switch actúa como router L3 de 2 patas)."""
    ip: IPAddr
    mac: EthAddr
    subnet: IPAddr          # dirección de red, ej. 192.168.1.0
    prefix_len: int         # ej. 24
    port: Optional[int] = None  # puerto físico del switch; solo la pública lo tiene fijo


@dataclass(frozen=True)
class NatConfig:
    public: Interface
    private: Interface
    # Pool de puertos públicos
    port_min: int = 49152
    port_max: int = 65535
    # Timeouts (segundos) de los flujos / mapeos
    tcp_idle_timeout: int = 120
    udp_idle_timeout: int = 30
    icmp_idle_timeout: int = 10
    flow_priority: int = 100
    # ARP
    arp_ttl: float = 300.0
    arp_request_timeout: float = 2.0
    arp_max_retries: int = 3

    # ---- helpers de consulta (TODOs: son una línea cada uno) -------------------------

    def is_private_ip(self, ip: IPAddr) -> bool:
        """True si `ip` pertenece a la subred privada del router.

        Qué implementar: ip.inNetwork(self.private.subnet, self.private.prefix_len).
        Hito: M1
        """
        raise NotImplementedError("TODO(M1): NatConfig.is_private_ip")

    def is_public_ip(self, ip: IPAddr) -> bool:
        """True si `ip` pertenece a la subred pública del router.

        Hito: M1
        """
        raise NotImplementedError("TODO(M1): NatConfig.is_public_ip")

    def is_router_ip(self, ip: IPAddr) -> bool:
        """True si `ip` es la IP de alguna de las dos interfaces del router
        (pública o privada). Se usa para decidir si responder ARP / ICMP localmente.

        Hito: M1
        """
        raise NotImplementedError("TODO(M1): NatConfig.is_router_ip")

    def idle_timeout_for(self, proto: int) -> int:
        """Devuelve el idle_timeout (seg) a usar para flujos del protocolo `proto`
        (PROTO_TCP / PROTO_UDP / PROTO_ICMP). Debe fallar claramente (ValueError)
        con protocolos no soportados.

        Hito: M1
        """
        raise NotImplementedError("TODO(M1): NatConfig.idle_timeout_for")


def load_config(path: str = DEFAULT_CONFIG_PATH) -> NatConfig:
    """Lee config/network.json y devuelve un NatConfig inmutable.

    Qué implementar:
      - Parsear las secciones "router", "nat" y "arp" (IGNORAR "topology": es solo de topo.py).
      - Convertir strings a IPAddr / EthAddr y separar "a.b.c.d/nn" en subnet + prefix_len.
      - Aplicar defaults de NatConfig si falta alguna clave opcional.
      - Validar: port_min < port_max, subredes pública y privada distintas, la interfaz
        pública debe traer "port".
      - Lanzar un error claro si el archivo no existe o es inválido.

    Hito: M1
    """
    raise NotImplementedError("TODO(M1): load_config")
