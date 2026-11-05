"""Configuración compartida por el controlador (y por topo.py, que lee el mismo JSON).

Decisión de diseño: NINGÚN valor de red está hardcodeado en el código del controlador.
Todo sale de config/network.json, así en la demo se pueden cambiar IPs/MACs sin tocar código.
El controlador solo conoce la configuración del *router* (interfaces) y los parámetros
del NAT/ARP; jamás las IPs/MACs de los hosts (esas se descubren por ARP).

Hito: M1
"""

from __future__ import annotations

import json
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

    # ---- helpers de consulta ---------------------------------------------------------

    def is_private_ip(self, ip: IPAddr) -> bool:
        """True si `ip` pertenece a la subred privada del router.

        Hito: M1
        """
        return ip.inNetwork(self.private.subnet, self.private.prefix_len)

    def is_public_ip(self, ip: IPAddr) -> bool:
        """True si `ip` pertenece a la subred pública del router.

        Hito: M1
        """
        return ip.inNetwork(self.public.subnet, self.public.prefix_len)

    def is_router_ip(self, ip: IPAddr) -> bool:
        """True si `ip` es la IP de alguna de las dos interfaces del router
        (pública o privada). Se usa para decidir si responder ARP / ICMP localmente.

        Hito: M1
        """
        return ip == self.public.ip or ip == self.private.ip

    def idle_timeout_for(self, proto: int) -> int:
        """Devuelve el idle_timeout (seg) a usar para flujos del protocolo `proto`
        (PROTO_TCP / PROTO_UDP / PROTO_ICMP). Debe fallar claramente (ValueError)
        con protocolos no soportados.

        Hito: M1
        """
        if proto == PROTO_TCP:
            return self.tcp_idle_timeout
        if proto == PROTO_UDP:
            return self.udp_idle_timeout
        if proto == PROTO_ICMP:
            return self.icmp_idle_timeout
        raise ValueError(f"Protocolo IP no soportado por el NAT: {proto}")


def _parse_interface(name: str, d: dict, need_port: bool) -> Interface:
    """Convierte {"ip", "mac", "subnet": "a.b.c.d/nn", ["port"]} en un Interface."""
    try:
        subnet, prefix = d["subnet"].split("/")
        port = d.get("port")
        if need_port and port is None:
            raise ValueError(f"router.{name}: falta 'port' (puerto del switch)")
        return Interface(ip=IPAddr(d["ip"]), mac=EthAddr(d["mac"]),
                         subnet=IPAddr(subnet), prefix_len=int(prefix),
                         port=int(port) if port is not None else None)
    except KeyError as e:
        raise ValueError(f"router.{name}: falta la clave {e}") from None


def load_config(path: str = DEFAULT_CONFIG_PATH) -> NatConfig:
    """Lee config/network.json y devuelve un NatConfig inmutable.

    Ignora la sección "topology" (es solo de topo.py): el controlador no debe conocer
    IPs/MACs de los hosts. Las claves opcionales de "nat"/"arp" toman los defaults de NatConfig.
    Lanza ValueError con un mensaje claro si el archivo es inválido o inconsistente.

    Hito: M1
    """
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise ValueError(f"No existe el archivo de configuración: {path}") from None
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON inválido en {path}: {e}") from None

    try:
        router = raw["router"]
        public = _parse_interface("public", router["public"], need_port=True)
        private = _parse_interface("private", router["private"], need_port=False)
    except KeyError as e:
        raise ValueError(f"{path}: falta la clave {e}") from None

    nat = raw.get("nat", {})
    arp = raw.get("arp", {})
    defaults = NatConfig.__dataclass_fields__
    port_min, port_max = nat.get("port_range", [defaults["port_min"].default,
                                                  defaults["port_max"].default])

    def opt(section: dict, key: str, field: str):
        return section.get(key, defaults[field].default)

    cfg = NatConfig(
        public=public,
        private=private,
        port_min=int(port_min),
        port_max=int(port_max),
        tcp_idle_timeout=int(opt(nat, "tcp_idle_timeout", "tcp_idle_timeout")),
        udp_idle_timeout=int(opt(nat, "udp_idle_timeout", "udp_idle_timeout")),
        icmp_idle_timeout=int(opt(nat, "icmp_idle_timeout", "icmp_idle_timeout")),
        flow_priority=int(opt(nat, "flow_priority", "flow_priority")),
        arp_ttl=float(opt(arp, "ttl", "arp_ttl")),
        arp_request_timeout=float(opt(arp, "request_timeout", "arp_request_timeout")),
        arp_max_retries=int(opt(arp, "max_retries", "arp_max_retries")),
    )

    if not (0 < cfg.port_min < cfg.port_max <= 65535):
        raise ValueError(f"port_range inválido: [{cfg.port_min}, {cfg.port_max}]")
    if public.ip.inNetwork(private.subnet, private.prefix_len) or \
            private.ip.inNetwork(public.subnet, public.prefix_len):
        raise ValueError("Las subredes pública y privada no pueden solaparse")
    if not cfg.is_public_ip(public.ip) or not cfg.is_private_ip(private.ip):
        raise ValueError("La IP de cada interfaz debe pertenecer a su propia subred")
    return cfg
