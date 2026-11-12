"""Pruebas unitarias del despacho y clasificación, sin switch ni Mininet."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pox.lib.addresses import IPAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet

from natsdn.config import load_config
from natsdn.nat_router import NatRouter, PacketClass


@pytest.fixture
def router():
    return NatRouter(Mock(), load_config())


def classify(router, src, dst, port):
    packet = ipv4(srcip=IPAddr(src), dstip=IPAddr(dst))
    return router.classify_ip(packet, port)


@pytest.mark.parametrize("src,dst,port,expected", [
    ("192.168.1.2", "200.0.0.1", 2, PacketClass.OUTBOUND),
    ("192.168.1.3", "200.0.0.1", 3, PacketClass.OUTBOUND),
    ("200.0.0.1", "200.0.0.254", 1, PacketClass.INBOUND),
    ("192.168.1.2", "192.168.1.254", 2, PacketClass.TO_ROUTER),
    ("192.168.1.2", "200.0.0.254", 2, PacketClass.TO_ROUTER),
    ("200.0.0.1", "192.168.1.254", 1, PacketClass.TO_ROUTER),
    ("192.168.1.2", "192.168.1.3", 2, PacketClass.OTHER),
    ("192.168.1.2", "200.0.0.1", 1, PacketClass.OTHER),
    ("200.0.0.1", "200.0.0.2", 1, PacketClass.OTHER),
    ("200.0.0.1", "192.168.1.2", 1, PacketClass.OTHER),
    ("200.0.0.1", "200.0.0.2", 2, PacketClass.OTHER),
    ("192.168.1.2", "203.0.113.1", 2, PacketClass.OUTBOUND),
])
def test_classify_ip(router, src, dst, port, expected):
    assert classify(router, src, dst, port) is expected


def test_classify_ip_uses_configured_networks_and_public_port(router):
    router.cfg = replace(
        router.cfg,
        public=replace(router.cfg.public, ip=IPAddr("198.51.100.254"),
                       subnet=IPAddr("198.51.100.0"), port=7),
        private=replace(router.cfg.private, ip=IPAddr("10.0.0.254"),
                        subnet=IPAddr("10.0.0.0")),
    )
    assert classify(router, "10.0.0.2", "198.51.100.1", 1) is PacketClass.OUTBOUND
    assert classify(router, "198.51.100.1", "198.51.100.254", 7) is PacketClass.INBOUND
    assert classify(router, "10.0.0.2", "10.0.0.254", 1) is PacketClass.TO_ROUTER
    assert classify(router, "10.0.0.2", "10.0.0.3", 1) is PacketClass.OTHER


@pytest.mark.parametrize("ethertype,parsed,expected", [
    (ethernet.ARP_TYPE, True, "arp"),
    (ethernet.IP_TYPE, True, "ipv4"),
    (ethernet.IPV6_TYPE, True, None),
    (ethernet.LLDP_TYPE, True, None),
    (ethernet.ARP_TYPE, False, None),
    (ethernet.IP_TYPE, False, None),
])
def test_packet_in_dispatch(router, caplog, ethertype, parsed, expected):
    packet = ethernet(type=ethertype)
    packet.parsed = parsed
    event = SimpleNamespace(parsed=packet, port=3)
    router.arp.handle_arp = Mock()
    router.handle_ip = Mock()

    with caplog.at_level("DEBUG", logger="natsdn"):
        assert router._handle_PacketIn(event) is None

    if expected == "arp":
        router.arp.handle_arp.assert_called_once_with(packet, event.port)
        router.handle_ip.assert_not_called()
    elif expected == "ipv4":
        router.handle_ip.assert_called_once_with(event)
        router.arp.handle_arp.assert_not_called()
    else:
        router.arp.handle_arp.assert_not_called()
        router.handle_ip.assert_not_called()
        records = [record for record in caplog.records if record.name == "natsdn"]
        assert len(records) == 1
        if not parsed:
            assert records[0].levelname == "WARNING"
            assert records[0].getMessage() == "Trama no parseada descartada en puerto 3"
        else:
            assert records[0].levelname == "DEBUG"
            assert records[0].getMessage() == (
                f"Ethertype 0x{ethertype:04x} ignorado en puerto 3"
            )
    router.connection.send.assert_not_called()


@pytest.mark.parametrize("src,dst,port,handler", [
    ("192.168.1.2", "200.0.0.1", 2, "handle_outbound"),
    ("200.0.0.1", "200.0.0.254", 1, "handle_inbound"),
    ("192.168.1.2", "192.168.1.254", 2, None),
    ("192.168.1.2", "192.168.1.3", 2, None),
])
@pytest.mark.parametrize("entrypoint", ["handle_ip", "_handle_PacketIn"])
def test_ipv4_dispatch(router, caplog, src, dst, port, handler, entrypoint):
    packet = ethernet(type=ethernet.IP_TYPE)
    packet.parsed = True
    ip_packet = ipv4(srcip=IPAddr(src), dstip=IPAddr(dst))
    ip_packet.parsed = True
    packet.payload = ip_packet
    raw_data = b"original packet bytes"
    event = SimpleNamespace(parsed=packet, port=port,
                            ofp=SimpleNamespace(data=raw_data))
    handlers = {name: Mock() for name in (
        "handle_outbound", "handle_inbound", "handle_to_router",
    )}
    for name, mock in handlers.items():
        setattr(router, name, mock)

    with caplog.at_level("DEBUG", logger="natsdn"):
        assert getattr(router, entrypoint)(event) is None

    for name, mock in handlers.items():
        if name == handler:
            mock.assert_called_once_with(packet, port, raw_data)
            assert mock.call_args.args[0] is packet
            assert mock.call_args.args[2] is raw_data
        else:
            mock.assert_not_called()
    if handler is None:
        assert caplog.record_tuples == [(
            "natsdn", 10,
            f"IPv4 {src} -> {dst} descartado en puerto {port}: "
            f"{'TO_ROUTER' if router.cfg.is_router_ip(IPAddr(dst)) else 'OTHER'}",
        )]
    router.connection.send.assert_not_called()


@pytest.mark.parametrize("src,dst,port", [
    ("192.168.1.2", "192.168.1.254", 2),
    ("192.168.1.2", "200.0.0.254", 2),
    ("200.0.0.1", "192.168.1.254", 1),
])
def test_packet_in_drops_to_router_without_side_effects(router, caplog, src, dst, port):
    packet = ethernet(type=ethernet.IP_TYPE)
    packet.parsed = True
    packet.payload = ipv4(srcip=IPAddr(src), dstip=IPAddr(dst))
    packet.payload.parsed = True
    event = SimpleNamespace(parsed=packet, port=port,
                            ofp=SimpleNamespace(data=b"to router"))
    router.arp.resolve = Mock()
    router.nat_table.get_or_create_outbound = Mock()
    router.nat_table.lookup_inbound = Mock()

    with caplog.at_level("DEBUG", logger="natsdn"):
        assert router._handle_PacketIn(event) is None

    assert caplog.record_tuples == [(
        "natsdn", 10,
        f"IPv4 {src} -> {dst} descartado en puerto {port}: TO_ROUTER",
    )]
    router.connection.send.assert_not_called()
    router.arp.resolve.assert_not_called()
    router.nat_table.get_or_create_outbound.assert_not_called()
    router.nat_table.lookup_inbound.assert_not_called()
    assert list(router.nat_table.entries()) == []


@pytest.mark.parametrize("has_ipv4", [False, True])
def test_handle_ip_discards_missing_or_unparsed_ipv4(router, caplog, has_ipv4):
    packet = ethernet(type=ethernet.IP_TYPE)
    if has_ipv4:
        packet.payload = ipv4()
        packet.payload.parsed = False
    router.classify_ip = Mock()
    router.handle_outbound = Mock()
    router.handle_inbound = Mock()
    router.handle_to_router = Mock()
    event = SimpleNamespace(parsed=packet, port=2,
                            ofp=SimpleNamespace(data=b"incomplete"))

    with caplog.at_level("WARNING", logger="natsdn"):
        assert router.handle_ip(event) is None

    assert caplog.record_tuples == [(
        "natsdn", 30, "Paquete IPv4 ausente o no parseado descartado en puerto 2",
    )]
    router.classify_ip.assert_not_called()
    router.handle_outbound.assert_not_called()
    router.handle_inbound.assert_not_called()
    router.handle_to_router.assert_not_called()
    router.connection.send.assert_not_called()
