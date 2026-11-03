#!/usr/bin/python3
"""Topología Mininet del TP2: 1 switch OpenFlow actuando como router/NAT.

                 Red pública                      Red privada
   ┌──────┐  port 1 (config)   ┌────┐  ports 2..N   ┌──────┐
   │  h1  ├────────────────────┤ s1 ├───────────────┤ h2   │
   └──────┘  IP 200.0.0.254    └────┘  IP 192.168.1.254 ├ h3 ┤ ... (N hosts privados)
             MAC 00:..:aa:aa:aa        MAC 00:..:bb:bb:bb

Todo (IPs, MACs, cantidad de hosts privados, puerto público) sale de config/network.json,
sección "router" y "topology", para poder cambiarlo en la demo sin tocar código.

Ejecución:  sudo python3 topo/topo.py [ruta/config.json]

Hito: M1
"""

import sys

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

CONFIG_PATH = "config/network.json"


def load_topology_config(path: str) -> dict:
    """Lee el JSON y devuelve el dict completo (esta vez sí se usa la sección "topology").
    Hito: M1"""
    raise NotImplementedError("TODO(M1): load_topology_config")


class NATTopo(Topo):
    def build(self, cfg: dict):
        """Construye la topología a partir de `cfg`.

        Qué implementar:
          - s1 = addSwitch('s1') (OpenFlow 1.0; protocols='OpenFlow10' si hace falta).
          - Host público (cfg["topology"]["public_host"]) con ip, mac y
            defaultRoute 'via <IP pública del router>'. Enlazarlo a s1 FIJANDO el puerto del
            switch: addLink(h_pub, s1, port2=cfg["router"]["public"]["port"]).
          - Por cada host de cfg["topology"]["private_hosts"]: ip, mac y defaultRoute 'via <IP
            privada del router>'; enlazarlo a s1 (los puertos se asignan después del público).
          - La cantidad de hosts privados es la longitud de la lista (>= 2 para probar PAT).
        Hito: M1
        """
        raise NotImplementedError("TODO(M1): NATTopo.build")


def disable_ipv6(node) -> None:
    """Deshabilita IPv6 en un nodo (igual que topo.py de la cátedra: tres sysctl
    net.ipv6.conf.{all,default,lo}.disable_ipv6=1 vía node.cmd). Hito: M1"""
    raise NotImplementedError("TODO(M1): disable_ipv6")


def run(config_path: str = CONFIG_PATH) -> None:
    """Levanta la red y abre la CLI.

    Qué implementar:
      - cfg = load_topology_config(); net = Mininet(topo=NATTopo(cfg=cfg),
        controller=RemoteController, link=TCLink); net.start().
      - disable_ipv6() en todos los hosts y en s1.
      - NO usar setARP(): el controlador debe resolver todo por ARP dinámico (requisito del TP).
        Eliminar las entradas del topo.py original ("Entradas ARP para debug").
      - CLI(net); net.stop().
    Hito: M1
    """
    raise NotImplementedError("TODO(M1): run")


if __name__ == '__main__':
    setLogLevel('info')
    run(sys.argv[1] if len(sys.argv) > 1 else CONFIG_PATH)
