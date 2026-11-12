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

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

from natsdn.arp_handler import ArpHandler
from natsdn.arp_table import ArpTable
from natsdn.config import DEFAULT_CONFIG_PATH, NatConfig, load_config
from natsdn.flow_installer import FlowInstaller
from natsdn.log_utils import YELLOW, log, log_color
from natsdn.nat_table import Direction, NatTable
from natsdn.packet_utils import extract_transport
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
        """Registra expiraciones idle/hard sin reenviar ni reinstalar flujos.

        Ignora borrados explícitos, otros motivos y cookies de mapeos ya liberados.
        NatTable conserva el mapeo y su puerto mientras el otro sentido siga activo.
        Hito: M4
        """
        if event.ofp.reason not in (of.OFPRR_IDLE_TIMEOUT, of.OFPRR_HARD_TIMEOUT):
            return

        entry_id, direction = FlowInstaller.parse_cookie(event.ofp.cookie)
        entry = self.nat_table.get_by_id(entry_id)
        if entry is None:
            log.debug("FlowRemoved ignorado: mapeo %s sentido %s desconocido o ya liberado",
                      entry_id, direction.name)
            return

        released = self.nat_table.on_flow_removed(entry, direction)
        log.info("FlowRemoved: mapeo %s sentido %s %s", entry_id, direction.name,
                 "liberado" if released else "conservado (otro sentido activo)")

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
            log.debug("IPv4 %s -> %s descartado en puerto %s: TO_ROUTER",
                      ip_pkt.srcip, ip_pkt.dstip, in_port)
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
        """Traduce TCP/UDP hacia la subred pública; otros transportes se descartan.

        Resuelve ambas MAC antes de instalar los dos flujos y reenvía los bytes originales
        con las acciones salientes. Cada continuación ARP valida la identidad del mapeo.
        Un fallo cancela este paquete y libera solo su mapeo nuevo, aún sin flujos activos;
        nunca elimina un mapeo previo o activado por otro paquete mientras esperaba ARP.
        Hito: M4
        """
        ip_pkt = packet.find("ipv4")
        if ip_pkt is None or not ip_pkt.parsed:
            log.warning("IPv4 saliente ausente o no parseado en puerto %s", in_port)
            return
        info = extract_transport(ip_pkt)
        if info is None:
            log.warning("Transporte saliente no soportado o no parseado: %s", ip_pkt.protocol)
            return
        if not self.cfg.is_public_ip(ip_pkt.dstip):
            log.warning("Destino saliente fuera de la subred pública: %s", ip_pkt.dstip)
            return

        previous_ids = {entry.entry_id for entry in self.nat_table.entries()}
        entry = self.nat_table.get_or_create_outbound(
            info.proto, ip_pkt.srcip, info.src_port, in_port, ip_pkt.dstip, info.dst_port)
        if entry is None:
            log.warning("Pool NAT agotado para protocolo %s", info.proto)
            return
        created = entry.entry_id not in previous_ids
        finished = False
        public_resolved = False

        def is_current():
            return not finished and self.nat_table.get_by_id(entry.entry_id) is entry

        def on_failed():
            nonlocal finished
            if finished:
                return
            finished = True
            if (created and self.nat_table.get_by_id(entry.entry_id) is entry
                    and not any(entry.flow_active.values())):
                self.nat_table.release(entry)
            log.warning("Resolución ARP saliente fallida para mapeo %s", entry.entry_id)

        def on_public_resolved(public_mac, public_port):
            nonlocal public_resolved
            if not is_current() or public_resolved:
                return
            public_resolved = True

            def on_private_resolved(private_mac, private_port):
                nonlocal finished
                if not is_current():
                    return
                if private_port != entry.priv_switch_port:
                    on_failed()
                    return
                finished = True  # callbacks duplicados no instalan ni envían dos veces
                actions = self.flows.install_outbound(entry, public_mac)
                self.nat_table.mark_flow_installed(entry, Direction.OUTBOUND)
                self.flows.install_inbound(entry, private_mac)
                self.nat_table.mark_flow_installed(entry, Direction.INBOUND)
                self.io.send_packet(raw_data, actions, in_port)

            private_host = self.arp_table.lookup(entry.priv_ip)
            if private_host is not None:
                on_private_resolved(private_host.mac, private_host.port)
            else:
                self.arp.resolve(entry.priv_ip, in_port,
                                 on_resolved=on_private_resolved, on_failed=on_failed)

        self.arp.resolve(entry.remote_ip, self.cfg.public.port,
                         on_resolved=on_public_resolved, on_failed=on_failed)

    def handle_inbound(self, packet: ethernet, in_port: int, raw_data: bytes) -> None:
        """Reinstala solo el flujo entrante de un mapeo TCP/UDP existente.

        Valida interfaz pública y origen remoto antes de resolver la MAC privada. Tras ARP,
        comprueba identidad del mapeo y puerto privado, marca INBOUND activo y reenvía los
        bytes originales con las mismas acciones. Cada invocación reenvía como máximo una
        vez; un fallo cancela el paquete sin liberar el mapeo ni afectar el flujo saliente.
        Tráfico no solicitado o no parseado se descarta con log, sin crear conexiones.
        Hito: M4
        """
        ip_pkt = packet.find("ipv4")
        if ip_pkt is None or not ip_pkt.parsed:
            log.warning("IPv4 entrante ausente o no parseado en puerto %s", in_port)
            return
        info = extract_transport(ip_pkt)
        if info is None:
            log.warning("Transporte entrante no soportado o no parseado: %s", ip_pkt.protocol)
            return
        if in_port != self.cfg.public.port or ip_pkt.dstip != self.cfg.public.ip:
            log.warning("IPv4 entrante fuera de la interfaz pública en puerto %s", in_port)
            return

        entry = self.nat_table.lookup_inbound(info.proto, info.dst_port)
        if entry is None:
            log.warning("Tráfico entrante sin mapeo: protocolo %s, puerto %s",
                        info.proto, info.dst_port)
            return
        if ip_pkt.srcip != entry.remote_ip or info.src_port != entry.remote_port:
            log.warning("Origen entrante no coincide con mapeo %s", entry.entry_id)
            return
        finished = False

        def is_current():
            return not finished and self.nat_table.get_by_id(entry.entry_id) is entry

        def on_failed():
            nonlocal finished
            if not is_current():
                return
            finished = True
            log.warning("Resolución ARP entrante fallida para mapeo %s", entry.entry_id)

        def on_resolved(private_mac, private_port):
            nonlocal finished
            if not is_current():
                return
            if private_port != entry.priv_switch_port:
                on_failed()
                return
            finished = True  # callbacks duplicados no instalan ni envían dos veces
            actions = self.flows.install_inbound(entry, private_mac)
            self.nat_table.mark_flow_installed(entry, Direction.INBOUND)
            self.io.send_packet(raw_data, actions, in_port)

        self.arp.resolve(entry.priv_ip, entry.priv_switch_port,
                         on_resolved=on_resolved, on_failed=on_failed)

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
