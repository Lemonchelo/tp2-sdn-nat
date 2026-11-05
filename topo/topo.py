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

import json
import sys

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

CONFIG_PATH = "config/network.json"


def load_topology_config(path: str) -> dict:
    """Lee el JSON y devuelve el dict completo (esta vez sí se usa la sección "topology")."""
    with open(path) as f:
        cfg = json.load(f)
    if not cfg.get("topology", {}).get("private_hosts"):
        raise ValueError(f"{path}: topology.private_hosts debe tener al menos un host")
    return cfg


class NATTopo(Topo):
    def build(self, cfg: dict):
        """Construye la topología a partir de `cfg` (todo sale de config/network.json).

        Los puertos del switch se fijan explícitamente: el público es router.public.port
        y los privados toman los siguientes libres en orden de aparición en la lista.
        """
        router = cfg["router"]
        topo = cfg["topology"]
        pub_port = router["public"]["port"]
        pub_gw = router["public"]["ip"]
        priv_gw = router["private"]["ip"]

        s1 = self.addSwitch("s1")

        pub = topo["public_host"]
        h_pub = self.addHost(pub["name"], ip=pub["ip"], mac=pub["mac"],
                             defaultRoute=f"via {pub_gw}")
        self.addLink(h_pub, s1, port2=pub_port)

        next_port = 1
        for host in topo["private_hosts"]:
            if next_port == pub_port:
                next_port += 1
            h = self.addHost(host["name"], ip=host["ip"], mac=host["mac"],
                             defaultRoute=f"via {priv_gw}")
            self.addLink(h, s1, port2=next_port)
            next_port += 1


def disable_ipv6(node) -> None:
    """Deshabilita IPv6 en un nodo (igual que el topo.py de la cátedra)."""
    for scope in ("all", "default", "lo"):
        node.cmd(f"sysctl -w net.ipv6.conf.{scope}.disable_ipv6=1")


def run(config_path: str = CONFIG_PATH) -> None:
    """Levanta la red y abre la CLI. NO configura ARP estático: lo resuelve el controlador."""
    cfg = load_topology_config(config_path)
    net = Mininet(topo=NATTopo(cfg=cfg), controller=RemoteController, link=TCLink)
    net.start()

    for node in net.hosts + net.switches:
        disable_ipv6(node)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run(sys.argv[1] if len(sys.argv) > 1 else CONFIG_PATH)
