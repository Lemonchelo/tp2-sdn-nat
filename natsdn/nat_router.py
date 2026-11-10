"""Controlador POX: NAT saliente con PAT (reemplaza al protorouter.py de la cátedra).

Arranque:   python3 pox/pox.py log.level --DEBUG natsdn [--config=ruta.json]

Este módulo es solo el ORQUESTADOR: clasifica cada PacketIn y delega en ArpHandler / NatTable /
FlowInstaller. No contiene lógica de tablas ni de construcción de reglas.

FLUJO GENERAL (resumen; el detalle con diagramas está en docs/ARQUITECTURA.md §3):

  PacketIn
   ├─ ARP  ───────────────────────────────► ArpHandler.handle_arp()
   └─ IPv4 ─► classify_ip()
        ├─ OUTBOUND (viene de red privada, destino público)
        │     handle_outbound():
        │       1. extract_transport()  (no TCP/UDP -> ver ICMP / drop)
        │       2. NatTable.get_or_create_outbound()   (None -> pool agotado: drop)
        │       3. ArpHandler.resolve(remote_ip)        (MAC del servidor; puede encolar)
        │       4. FlowInstaller.install_outbound() + install_inbound()
        │       5. packet_out del paquete actual con las MISMAS acciones del flujo
        ├─ INBOUND  (viene del puerto público, destino IP pública del router)
        │     handle_inbound():
        │       1. NatTable.lookup_inbound()   (None -> tráfico no solicitado: drop)
        │       2. ArpHandler.resolve(priv_ip) (si la entrada ARP venció)
        │       3. FlowInstaller.install_inbound() y packet_out
        ├─ TO_ROUTER  (destino = IP del router, ej. ping al gateway)  -> handle_to_router()  [opcional]
        └─ OTHER      -> drop + log
  FlowRemoved ─► _handle_FlowRemoved(): actualizar NatTable (libera el mapeo cuando
                 expiraron los dos sentidos)

Después de instalados los flujos, el tráfico de la conexión NO vuelve a pasar por acá.

Hito: M4 (glue) — M5 (opcionales)
"""

from __future__ import annotations

import enum

from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

from natsdn.arp_handler import ArpHandler
from natsdn.arp_table import ArpTable
from natsdn.config import DEFAULT_CONFIG_PATH, NatConfig, load_config
from natsdn.flow_installer import FlowInstaller
from natsdn.log_utils import YELLOW, log, log_color
from natsdn.nat_table import NatTable
from natsdn.port_pool import PortPool
from natsdn.switch_io import SwitchIO


class PacketClass(enum.Enum):
    OUTBOUND = "outbound"      # privada -> pública (candidato a NAT)
    INBOUND = "inbound"        # pública -> IP pública del router (respuesta)
    TO_ROUTER = "to_router"    # destinado a una IP del propio router
    OTHER = "other"            # todo lo demás (se descarta)


class NatRouter:
    """Una instancia por switch conectado."""

    def __init__(self, connection, cfg: NatConfig):
        self.connection = connection
        self.cfg = cfg
        # Composición de componentes (ver docs/ARQUITECTURA.md §2)
        self.io = SwitchIO(connection)
        self.arp_table = ArpTable(cfg.arp_ttl)
        self.arp = ArpHandler(cfg, self.arp_table, self.io)
        self.nat_table = NatTable(PortPool(cfg.port_min, cfg.port_max))
        self.flows = FlowInstaller(cfg, self.io)
        connection.addListeners(self)

    # ---- eventos OpenFlow ------------------------------------------------------------

    def _handle_PacketIn(self, event) -> None:
        """Punto de entrada de todo paquete que el switch no sabe reenviar.

        Qué implementar:
          - Descartar (con log) tramas que POX no pudo parsear (event.parsed.parsed False).
          - Si es ARP (ethernet.ARP_TYPE): self.arp.handle_arp(packet, event.port).
          - Si es IPv4 (ethernet.IP_TYPE): self.handle_ip(event).
          - Cualquier otro ethertype (LLDP, IPv6, ...): ignorar con log DEBUG.
        Hito: M4
        """
        packet = event.parsed
        if not packet.parsed:
            log.warning("Trama no parseada descartada en puerto %s", event.port)
            return

        if packet.type == ethernet.ARP_TYPE:
            self.arp.handle_arp(packet, event.port)
        elif packet.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log.debug("Ethertype 0x%04x ignorado en puerto %s", packet.type, event.port)

    def _handle_FlowRemoved(self, event) -> None:
        """El switch avisa que expiró (o se borró) un flujo que instalamos con SEND_FLOW_REM.

        Qué implementar:
          - Descartar si event.ofp.reason no es de expiración por idle/hard timeout (si lo
            borramos nosotros con remove_flows() ya actualizamos la tabla).
          - FlowInstaller.parse_cookie(event.ofp.cookie) -> (entry_id, direction).
          - NatTable.get_by_id() y NatTable.on_flow_removed(entry, direction).
          - Loguear el estado (mapeo liberado / sigue vivo por el otro sentido).
        Hito: M4
        """
        raise NotImplementedError("TODO(M4): NatRouter._handle_FlowRemoved")

    # ---- IPv4 ------------------------------------------------------------------------

    def handle_ip(self, event) -> None:
        """Despacha un PacketIn IPv4 según classify_ip().

        Qué implementar: extraer packet = event.parsed, in_port = event.port y los bytes
        originales (event.ofp.data) y llamar al handler que corresponda. Los handlers reciben
        (packet, in_port, raw_data) y NO el event, para poder re-inyectar paquetes que
        estuvieron esperando un ARP.
        Hito: M4
        """
        packet = event.parsed
        in_port = event.port
        ip_pkt = packet.find("ipv4")
        if ip_pkt is None or not ip_pkt.parsed:
            log.warning("Paquete IPv4 ausente o no parseado descartado en puerto %s", in_port)
            return

        raw_data = event.ofp.data
        packet_class = self.classify_ip(ip_pkt, in_port)
        if packet_class == PacketClass.OUTBOUND:
            self.handle_outbound(packet, in_port, raw_data)
        elif packet_class == PacketClass.INBOUND:
            self.handle_inbound(packet, in_port, raw_data)
        elif packet_class == PacketClass.TO_ROUTER:
            self.handle_to_router(packet, in_port, raw_data)
        else:
            log.debug("IPv4 %s -> %s descartado en puerto %s: OTHER",
                      ip_pkt.srcip, ip_pkt.dstip, in_port)

    def classify_ip(self, ip_pkt: ipv4, in_port: int) -> PacketClass:
        """Clasifica un paquete IPv4.

        Reglas (en orden):
          - in_port == cfg.public.port y dst == IP pública del router        -> INBOUND
          - dst es IP del router (cfg.is_router_ip)                          -> TO_ROUTER
          - in_port != cfg.public.port, src en subred privada y dst NO
            privada                                                          -> OUTBOUND
          - cualquier otro caso (incluye privada->privada)                   -> OTHER

        INBOUND tiene prioridad: las respuestas NAT también tienen como destino
        una IP del router. La existencia del mapeo se valida en handle_inbound;
        la subred pública de los destinos salientes, en handle_outbound.
        Hito: M4
        """
        if in_port == self.cfg.public.port and ip_pkt.dstip == self.cfg.public.ip:
            return PacketClass.INBOUND
        if self.cfg.is_router_ip(ip_pkt.dstip):
            return PacketClass.TO_ROUTER
        if (in_port != self.cfg.public.port
                and self.cfg.is_private_ip(ip_pkt.srcip)
                and not self.cfg.is_private_ip(ip_pkt.dstip)):
            return PacketClass.OUTBOUND
        return PacketClass.OTHER

    def handle_outbound(self, packet: ethernet, in_port: int, raw_data: bytes) -> None:
        """Primer paquete (o paquete sin flujo) de una conexión privada -> pública.

        Qué implementar:
          1. info = extract_transport(ip_pkt). Si es None (ICMP u otro): handle_icmp() si está
             implementado, sino drop + log.
          2. Validar que ip_pkt.dstip esté en la subred pública (única red alcanzable en este
             TP; sino drop + log).
          3. entry = nat_table.get_or_create_outbound(...). Si None -> drop + log (pool agotado).
          4. self.arp.resolve(dstip, cfg.public.port, on_resolved=..., on_failed=...). En
             on_resolved(mac, port): flows.install_outbound(entry, mac) -> acciones;
             nat_table.mark_flow_installed(); self.io.send_packet(raw_data, acciones, in_port)
             para que el primer paquete salga ya traducido.
          5. Instalar también el flujo entrante: la MAC y el puerto del host privado se
             obtienen de la tabla ARP (se aprendieron cuando el host resolvió al gateway), con
             flows.install_inbound(entry, priv_mac). Si no están (caso raro) -> arp.resolve().
          6. on_failed: liberar el entry recién creado (nat_table.release) y loguear.
        Hito: M4
        """
        raise NotImplementedError("TODO(M4): NatRouter.handle_outbound")

    def handle_inbound(self, packet: ethernet, in_port: int, raw_data: bytes) -> None:
        """Paquete desde la red pública hacia la IP pública del router SIN flujo instalado.

        Caso normal: el flujo entrante ya existe y este handler no corre. Llega acá cuando
        (a) el flujo entrante expiró pero el mapeo sigue vivo, o (b) es tráfico no solicitado.

        Qué implementar:
          1. info = extract_transport(); entry = nat_table.lookup_inbound(info.proto, info.dst_port).
          2. Si no hay entry, o el remote_ip/remote_port del paquete no coinciden con los del
             entry -> drop + log (el NAT es saliente: no se aceptan conexiones entrantes nuevas).
          3. arp.resolve(entry.priv_ip, ...) -> en on_resolved: flows.install_inbound(entry, mac),
             nat_table.mark_flow_installed(), io.send_packet(raw_data, acciones, in_port).
        Hito: M4
        """
        raise NotImplementedError("TODO(M4): NatRouter.handle_inbound")

    # ---- Opcionales (M5) --------------------------------------------------------------

    def handle_to_router(self, packet: ethernet, in_port: int, raw_data: bytes) -> None:
        """OPCIONAL: paquete dirigido al propio router. Mínimo útil: responder ICMP echo
        (ping al gateway 192.168.1.254 / 200.0.0.254) construyendo el echo reply por packet_out.
        Si no se implementa, dropear con log. Hito: M5"""
        raise NotImplementedError("TODO(M5): NatRouter.handle_to_router")

    def handle_icmp(self, packet: ethernet, in_port: int, raw_data: bytes) -> None:
        """OPCIONAL: ICMP echo a través del NAT (ping de un host privado al servidor).

        Limitación de OpenFlow 1.0: no se puede matchear ni reescribir el 'id' del echo, así
        que NO se pueden instalar flujos por conexión. Opción sugerida: el controlador traduce
        cada paquete (packet_out) usando el 'id' de ICMP como "puerto" en una tabla aparte, sin
        instalar flujos. Es mucho tráfico al controlador pero el ping es solo de verificación.
        Hito: M5"""
        raise NotImplementedError("TODO(M5): NatRouter.handle_icmp")

    def dump_state(self) -> str:
        """OPCIONAL (muy útil para la demo/informe): devuelve un string con la tabla NAT y la
        tabla ARP actuales. Hito: M5"""
        raise NotImplementedError("TODO(M5): NatRouter.dump_state")


def launch(config: str = DEFAULT_CONFIG_PATH) -> None:
    """Entry point de POX: `python3 pox/pox.py natsdn --config=config/network.json`.

    La config se carga recién al conectarse el switch para que el controlador pueda arrancar
    (y el error de load_config sea claro en el log) aun con el esqueleto sin implementar.
    """

    def start_switch(event):
        cfg = load_config(config)
        log_color(YELLOW, f"Iniciando NatRouter para Switch {event.connection.dpid}")
        NatRouter(event.connection, cfg)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
