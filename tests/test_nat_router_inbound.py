"""NAT entrante con paquetes POX reales, sin switch ni timers ARP."""

from dataclasses import asdict, replace
from unittest.mock import Mock

import pytest
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

from natsdn.arp_handler import ArpHandler
from natsdn.config import load_config
from natsdn.flow_installer import FlowInstaller
from natsdn.nat_router import NatRouter
from natsdn.nat_table import Direction
from natsdn.switch_io import SwitchIO


PRIVATE_MAC = EthAddr("00:00:00:00:00:22")
REMOTE_MAC = EthAddr("00:00:00:00:00:11")


@pytest.fixture
def router():
    cfg = load_config()
    cfg = replace(cfg, port_min=50000, port_max=50001,
                  public=replace(cfg.public, port=7, ip=IPAddr("198.51.100.254"),
                                 subnet=IPAddr("198.51.100.0")))
    router = NatRouter(Mock(), cfg)
    router.nat_table.clock = lambda: 10.0
    router.arp = Mock(spec=ArpHandler)
    router.flows = Mock(spec=FlowInstaller)
    router.flows.install_inbound.return_value = [object(), object()]
    router.io = Mock(spec=SwitchIO)
    return router


def seed(router, proto=6, remote="198.51.100.1", active=False):
    entry = router.nat_table.get_or_create_outbound(
        proto, IPAddr("192.168.1.2"), 50000, 3, IPAddr(remote), 443)
    if active:
        router.nat_table.mark_flow_installed(entry, Direction.OUTBOUND)
    return entry


def packet_for(router, proto=6, src="198.51.100.1", src_port=443, dst_port=50000):
    transport = {6: tcp, 17: udp, 1: icmp}[proto]()
    if proto in (6, 17):
        transport.srcport, transport.dstport = src_port, dst_port
    frame = ethernet(type=ethernet.IP_TYPE, src=REMOTE_MAC, dst=router.cfg.public.mac)
    frame.payload = ipv4(srcip=IPAddr(src), dstip=router.cfg.public.ip,
                         protocol=proto, payload=transport)
    raw = frame.pack()
    return ethernet(raw=raw), raw


def snapshot(router):
    pool = router.nat_table.port_pool
    return ([asdict(e) for e in router.nat_table.entries()],
            [(pool.available(p), [pool.in_use(p, n) for n in (50000, 50001)])
             for p in (6, 17)])


def no_forward(router):
    assert router.flows.mock_calls == []
    assert router.io.mock_calls == []
    router.connection.send.assert_not_called()


def callbacks(router, index=0):
    kwargs = router.arp.resolve.call_args_list[index].kwargs
    return kwargs["on_resolved"], kwargs["on_failed"]


def assert_resolution(router, entry):
    ok, fail = callbacks(router)
    router.arp.resolve.assert_called_once_with(
        entry.priv_ip, entry.priv_switch_port, on_resolved=ok, on_failed=fail)
    return ok, fail


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("outbound_active", [False, True])
def test_reinstall_only_inbound_and_forward_once(router, proto, deferred, outbound_active):
    entry = seed(router, proto, active=outbound_active)
    sibling = seed(router, 17 if proto == 6 else 6, remote="198.51.100.2")
    sibling_before = asdict(sibling)
    pool_before = snapshot(router)[1]
    packet, raw = packet_for(router, proto)
    order = []

    def install(actual_entry, mac):
        assert actual_entry is entry and mac == PRIVATE_MAC
        assert not entry.flow_active[Direction.INBOUND]
        order.append("install")
        return router.flows.install_inbound.return_value

    def send(data, actions, in_port):
        assert data is raw
        assert actions is router.flows.install_inbound.return_value
        assert in_port == router.cfg.public.port
        assert entry.flow_active == {Direction.INBOUND: True,
                                     Direction.OUTBOUND: outbound_active}
        assert entry.last_seen == 20.0
        order.append("send")

    router.flows.install_inbound.side_effect = install
    router.io.send_packet.side_effect = send
    if not deferred:
        router.arp.resolve.side_effect = lambda ip, port, on_resolved, on_failed: on_resolved(
            PRIVATE_MAC, port)
    router.nat_table.clock = lambda: 20.0
    before = snapshot(router)
    assert router.handle_inbound(packet, router.cfg.public.port, raw) is None
    ok, fail = assert_resolution(router, entry)
    if deferred:
        no_forward(router)
        assert snapshot(router) == before
        ok(PRIVATE_MAC, entry.priv_switch_port)
    after = snapshot(router)
    ok(PRIVATE_MAC, entry.priv_switch_port)
    fail()  # un fallo tardío no deshace el éxito
    ok(PRIVATE_MAC, entry.priv_switch_port + 1)
    assert snapshot(router) == after
    assert order == ["install", "send"]
    router.flows.install_inbound.assert_called_once_with(entry, PRIVATE_MAC)
    router.flows.install_outbound.assert_not_called()
    router.io.send_packet.assert_called_once_with(
        raw, router.flows.install_inbound.return_value, router.cfg.public.port)
    router.connection.send.assert_not_called()
    assert router.nat_table.lookup_inbound(proto, entry.public_port) is entry
    assert router.nat_table.get_by_id(entry.entry_id) is entry
    assert asdict(sibling) == sibling_before
    assert snapshot(router)[1] == pool_before


@pytest.mark.parametrize("case", [
    "missing_ip", "unparsed_ip", "icmp", "unknown", "unparsed_tcp", "unparsed_udp",
    "truncated", "fragment", "wrong_ingress", "wrong_destination",
    "remote_ip", "remote_port", "public_port", "protocol", "no_mapping",
])
def test_rejected_packet_has_no_side_effects(router, caplog, case):
    if case != "no_mapping":
        seed(router, active=True)
    proto = 1 if case == "icmp" else 17 if case in ("unparsed_udp", "protocol") else 6
    packet, raw = packet_for(
        router, proto, src="198.51.100.2" if case == "remote_ip" else "198.51.100.1",
        src_port=444 if case == "remote_port" else 443,
        dst_port=50001 if case == "public_port" else 50000)
    ip = packet.payload
    in_port = router.cfg.public.port
    if case == "missing_ip":
        packet.payload = b""
    elif case == "unparsed_ip":
        ip.parsed = False
    elif case == "unknown":
        ip.protocol, ip.payload = 99, b"unknown"
    elif case.startswith("unparsed_"):
        ip.payload.parsed = False
    elif case == "truncated":
        ip.payload = b"\x01"
    elif case == "fragment":
        ip.frag = 1
    elif case == "wrong_ingress":
        in_port = 1
    elif case == "wrong_destination":
        ip.dstip = IPAddr("200.0.0.254")
    before = snapshot(router)
    assert router.handle_inbound(packet, in_port, raw) is None
    assert snapshot(router) == before
    router.arp.resolve.assert_not_called()
    no_forward(router)
    messages = [r.getMessage() for r in caplog.records if r.name == "natsdn"]
    if case in ("missing_ip", "unparsed_ip"):
        expected = f"IPv4 entrante ausente o no parseado en puerto {in_port}"
    elif case in ("wrong_ingress", "wrong_destination"):
        expected = f"IPv4 entrante fuera de la interfaz pública en puerto {in_port}"
    elif case in ("remote_ip", "remote_port"):
        expected = "Origen entrante no coincide con mapeo 1"
    elif case in ("public_port", "protocol", "no_mapping"):
        expected = f"Tráfico entrante sin mapeo: protocolo {proto}, puerto {ip.payload.dstport}"
    else:
        expected = f"Transporte entrante no soportado o no parseado: {ip.protocol}"
    assert messages == [expected]
    assert seed(router, remote="198.51.100.3").entry_id == (1 if case == "no_mapping" else 2)


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("outbound_active", [False, True])
def test_arp_failure_cancels_packet_without_releasing_mapping(router, caplog, proto, outbound_active):
    entry = seed(router, proto, active=outbound_active)
    packet, raw = packet_for(router, proto)
    before = snapshot(router)
    router.handle_inbound(packet, router.cfg.public.port, raw)
    ok, fail = assert_resolution(router, entry)
    fail()
    fail()
    ok(PRIVATE_MAC, entry.priv_switch_port)
    no_forward(router)
    assert snapshot(router) == before
    assert router.nat_table.get_by_id(entry.entry_id) is entry
    assert router.nat_table.lookup_inbound(proto, entry.public_port) is entry
    assert caplog.messages == [f"Resolución ARP entrante fallida para mapeo {entry.entry_id}"]


@pytest.mark.parametrize("proto", [6, 17])
def test_wrong_private_port_cancels_packet_without_mutation(router, caplog, proto):
    entry = seed(router, proto, active=True)
    packet, raw = packet_for(router, proto)
    before = snapshot(router)
    router.handle_inbound(packet, router.cfg.public.port, raw)
    ok, fail = assert_resolution(router, entry)
    ok(PRIVATE_MAC, entry.priv_switch_port + 1)
    ok(PRIVATE_MAC, entry.priv_switch_port)
    fail()
    no_forward(router)
    assert snapshot(router) == before
    assert caplog.messages == [f"Resolución ARP entrante fallida para mapeo {entry.entry_id}"]


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("lifecycle", ["released", "expired", "replaced"])
def test_late_callbacks_cannot_revive_old_mapping(router, proto, lifecycle):
    entry = seed(router, proto, active=True)
    packet, raw = packet_for(router, proto)
    router.handle_inbound(packet, router.cfg.public.port, raw)
    ok, fail = assert_resolution(router, entry)
    if lifecycle == "expired":
        router.nat_table.clock = lambda: 100.0
        assert router.nat_table.expire_stale(30) == [entry]
    else:
        router.nat_table.release(entry)
    replacement = seed(router, proto) if lifecycle == "replaced" else None
    before = snapshot(router)
    ok(PRIVATE_MAC, entry.priv_switch_port)
    fail()
    ok(PRIVATE_MAC, entry.priv_switch_port)
    no_forward(router)
    assert snapshot(router) == before
    assert router.nat_table.get_by_id(entry.entry_id) is None
    assert not entry.flow_active[Direction.INBOUND]
    if replacement is not None:
        assert replacement.public_port == entry.public_port
        assert router.nat_table.lookup_inbound(proto, entry.public_port) is replacement
    else:
        assert router.nat_table.lookup_inbound(proto, entry.public_port) is None


def test_failed_waiter_does_not_cancel_another_packet(router):
    entry = seed(router, active=True)
    packet, raw = packet_for(router)
    router.handle_inbound(packet, router.cfg.public.port, raw)
    first_ok, first_fail = callbacks(router)
    router.handle_inbound(packet, router.cfg.public.port, raw)
    second_ok, second_fail = callbacks(router, 1)
    second_ok(PRIVATE_MAC, entry.priv_switch_port)
    before = snapshot(router)
    first_fail()
    first_ok(PRIVATE_MAC, entry.priv_switch_port)
    second_fail()
    assert snapshot(router) == before
    router.flows.install_inbound.assert_called_once_with(entry, PRIVATE_MAC)
    router.flows.install_outbound.assert_not_called()
    router.io.send_packet.assert_called_once_with(
        raw, router.flows.install_inbound.return_value, router.cfg.public.port)
    assert router.io.send_packet.call_args.args[0] is raw
    assert router.io.send_packet.call_args.args[1] is router.flows.install_inbound.return_value
    assert entry.flow_active == {Direction.OUTBOUND: True, Direction.INBOUND: True}
