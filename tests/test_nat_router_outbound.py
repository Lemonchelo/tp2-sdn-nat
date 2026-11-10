"""NAT saliente sin switch, timers ni modificaciones de ArpHandler."""

from dataclasses import asdict, replace
from unittest.mock import Mock, call

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


PUBLIC_MAC = EthAddr("00:00:00:00:00:11")
PRIVATE_MAC = EthAddr("00:00:00:00:00:22")


def packet_for(proto=6, src="192.168.1.2", dst="200.0.0.1"):
    transport = {6: tcp, 17: udp, 1: icmp}[proto]()
    if proto in (6, 17):
        transport.srcport, transport.dstport = 50000, 443
    frame = ethernet(type=ethernet.IP_TYPE, src=PRIVATE_MAC, dst=PUBLIC_MAC)
    frame.payload = ipv4(srcip=IPAddr(src), dstip=IPAddr(dst),
                         protocol=proto, payload=transport)
    raw = frame.pack()
    return ethernet(raw=raw), raw


@pytest.fixture
def router():
    cfg = replace(load_config(), port_min=50000, port_max=50001)
    router = NatRouter(Mock(), cfg)
    router.nat_table.clock = lambda: 10.0
    router.arp = Mock(spec=ArpHandler)
    router.flows = Mock(spec=FlowInstaller)
    router.flows.install_outbound.return_value = [object(), object()]
    router.io = Mock(spec=SwitchIO)
    return router


def seed(router, proto=6, src="192.168.1.2", port=2):
    return router.nat_table.get_or_create_outbound(
        proto, IPAddr(src), 50000, port, IPAddr("200.0.0.1"), 443)


def snapshot(router):
    pool = router.nat_table.port_pool
    return ([asdict(e) for e in router.nat_table.entries()],
            [(pool.available(p), [pool.in_use(p, n) for n in (50000, 50001)])
             for p in (6, 17)])


def no_forward(router):
    router.flows.install_outbound.assert_not_called()
    router.flows.install_inbound.assert_not_called()
    router.io.send_packet.assert_not_called()
    router.connection.send.assert_not_called()


def callbacks(router, index=0):
    kwargs = router.arp.resolve.call_args_list[index].kwargs
    return kwargs["on_resolved"], kwargs["on_failed"]


def assert_forward(router, entry, raw, port=2):
    router.flows.install_outbound.assert_called_once_with(entry, PUBLIC_MAC)
    router.flows.install_inbound.assert_called_once_with(entry, PRIVATE_MAC)
    actions = router.flows.install_outbound.return_value
    router.io.send_packet.assert_called_once_with(raw, actions, port)
    assert router.io.send_packet.call_args.args[0] is raw
    assert router.io.send_packet.call_args.args[1] is actions
    assert entry.flow_active == {Direction.OUTBOUND: True, Direction.INBOUND: True}
    assert router.nat_table.get_by_id(entry.entry_id) is entry
    assert router.nat_table.lookup_inbound(entry.proto, entry.public_port) is entry


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("private_cached", [True, False])
@pytest.mark.parametrize("deferred", [True, False])
def test_resolve_both_sides_before_installing(router, proto, private_cached, deferred):
    packet, raw = packet_for(proto)
    if private_cached:
        router.arp_table.learn(packet.payload.srcip, PRIVATE_MAC, 2)
    if not deferred:
        def resolve(ip, port, on_resolved, on_failed):
            no_forward(router)
            on_resolved(PUBLIC_MAC if port == router.cfg.public.port else PRIVATE_MAC, port)
        router.arp.resolve.side_effect = resolve
    assert router.handle_outbound(packet, 2, raw) is None
    entry, = router.nat_table.entries()
    assert (entry.proto, entry.priv_ip, entry.priv_port, entry.priv_switch_port,
            entry.remote_ip, entry.remote_port) == (
                proto, packet.payload.srcip, 50000, 2, packet.payload.dstip, 443)
    if deferred:
        no_forward(router)
        public_ok, _ = callbacks(router)
        public_ok(PUBLIC_MAC, router.cfg.public.port)
        if not private_cached:
            no_forward(router)
            private_ok, _ = callbacks(router, 1)
            private_ok(PRIVATE_MAC, 2)
            private_ok(PRIVATE_MAC, 2)  # duplicados no reenvían el paquete otra vez
        public_ok(PUBLIC_MAC, router.cfg.public.port)
    expected = [call(packet.payload.dstip, router.cfg.public.port,
                     on_resolved=callbacks(router)[0], on_failed=callbacks(router)[1])]
    if not private_cached:
        expected.append(call(packet.payload.srcip, 2,
                             on_resolved=callbacks(router, 1)[0], on_failed=callbacks(router, 1)[1]))
    assert router.arp.resolve.call_args_list == expected
    assert_forward(router, entry, raw)


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize("side", ["public", "private"])
def test_arp_failure_drops_packet_and_only_releases_its_new_mapping(router, caplog, existing, side):
    previous = seed(router) if existing else None
    packet, raw = packet_for()
    router.handle_outbound(packet, 2, raw)
    entry, = router.nat_table.entries()
    if side == "private":
        callbacks(router)[0](PUBLIC_MAC, router.cfg.public.port)
    ok, fail = callbacks(router, 0 if side == "public" else 1)
    before = snapshot(router)
    fail()
    assert caplog.records
    ok(PRIVATE_MAC if side == "private" else PUBLIC_MAC, 2)
    no_forward(router)
    if existing:
        assert snapshot(router) == before
        assert router.nat_table.get_by_id(entry.entry_id) is previous
    else:
        assert list(router.nat_table.entries()) == []
        assert router.nat_table.lookup_inbound(6, entry.public_port) is None
        assert router.nat_table.port_pool.available(6) == 2
        assert not router.nat_table.port_pool.in_use(6, entry.public_port)
    assert router.arp.resolve.call_count == (2 if side == "private" else 1)


@pytest.mark.parametrize("cached", [True, False])
def test_wrong_private_switch_port_drops_without_partial_flows(router, caplog, cached):
    packet, raw = packet_for()
    if cached:
        router.arp_table.learn(packet.payload.srcip, PRIVATE_MAC, 3)
    router.handle_outbound(packet, 2, raw)
    callbacks(router)[0](PUBLIC_MAC, router.cfg.public.port)
    if not cached:
        callbacks(router, 1)[0](PRIVATE_MAC, 3)
    no_forward(router)
    assert list(router.nat_table.entries()) == []
    assert router.nat_table.port_pool.available(6) == 2
    assert caplog.records


@pytest.mark.parametrize("case", ["missing_ip", "unparsed_ip", "icmp", "unknown",
                                  "unparsed_tcp", "unparsed_udp", "truncated", "fragment", "outside"])
def test_rejected_packet_has_no_side_effects(router, caplog, case):
    packet, raw = packet_for(1 if case == "icmp" else 17 if case == "unparsed_udp" else 6)
    ip = packet.payload
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
    elif case == "outside":
        ip.dstip = IPAddr("203.0.113.1")
    before = snapshot(router)
    assert router.handle_outbound(packet, 2, raw) is None
    assert snapshot(router) == before
    router.arp.resolve.assert_not_called()
    no_forward(router)
    assert caplog.records
    assert seed(router).entry_id == 1  # rechazo no consume IDs


def test_pool_exhaustion_does_not_change_public_state_or_counters(router, caplog):
    entries = [seed(router, src=f"192.168.1.{n}", port=n) for n in (2, 3)]
    before = snapshot(router)
    packet, raw = packet_for(src="192.168.1.4")
    assert router.handle_outbound(packet, 4, raw) is None
    assert snapshot(router) == before
    router.arp.resolve.assert_not_called()
    no_forward(router)
    assert caplog.records
    router.nat_table.release(entries[0])
    assert seed(router, src="192.168.1.4", port=4).entry_id == 3


@pytest.mark.parametrize("proto", [6, 17])
def test_tuple_reuse_and_distinct_hosts_with_same_source_port(router, proto):
    router.arp.resolve.side_effect = lambda ip, port, on_resolved, on_failed: on_resolved(
        PUBLIC_MAC if port == router.cfg.public.port else PRIVATE_MAC, port)
    packet, raw = packet_for(proto)
    router.handle_outbound(packet, 2, raw)
    original, = router.nat_table.entries()
    router.handle_outbound(packet, 2, raw)
    assert list(router.nat_table.entries()) == [original]
    other, other_raw = packet_for(proto, src="192.168.1.3")
    router.handle_outbound(other, 3, other_raw)
    first, second = router.nat_table.entries()
    assert first is original
    assert second.priv_ip == other.payload.srcip and second.priv_switch_port == 3
    assert first.public_port != second.public_port
    assert router.nat_table.port_pool.available(proto) == 0
    assert router.io.send_packet.call_args_list == [
        call(raw, router.flows.install_outbound.return_value, 2),
        call(raw, router.flows.install_outbound.return_value, 2),
        call(other_raw, router.flows.install_outbound.return_value, 3)]
    assert all(all(e.flow_active.values()) for e in (first, second))


@pytest.mark.parametrize("side", ["public", "private"])
@pytest.mark.parametrize("replace_entry", [False, True])
def test_late_callback_cannot_resurrect_released_or_replaced_entry(router, side, replace_entry):
    packet, raw = packet_for()
    router.handle_outbound(packet, 2, raw)
    old, = router.nat_table.entries()
    if side == "private":
        callbacks(router)[0](PUBLIC_MAC, router.cfg.public.port)
    ok, fail = callbacks(router, 0 if side == "public" else 1)
    router.nat_table.release(old)
    replacement = seed(router) if replace_entry else None
    before = snapshot(router)
    ok(PRIVATE_MAC if side == "private" else PUBLIC_MAC, 2)
    fail()
    no_forward(router)
    assert snapshot(router) == before
    assert router.nat_table.get_by_id(old.entry_id) is None
    if replacement:
        assert router.nat_table.get_by_id(replacement.entry_id) is replacement


@pytest.mark.parametrize("side", ["public", "private"])
def test_creator_failure_after_sibling_success_preserves_active_mapping(router, side):
    packet, raw = packet_for()
    router.handle_outbound(packet, 2, raw)
    if side == "private":
        callbacks(router)[0](PUBLIC_MAC, router.cfg.public.port)
    late_ok, fail = callbacks(router, 0 if side == "public" else 1)
    start = router.arp.resolve.call_count
    router.handle_outbound(packet, 2, raw)
    callbacks(router, start)[0](PUBLIC_MAC, router.cfg.public.port)
    callbacks(router, start + 1)[0](PRIVATE_MAC, 2)
    entry, = router.nat_table.entries()
    before = snapshot(router)
    fail()
    late_ok(PRIVATE_MAC if side == "private" else PUBLIC_MAC, 2)
    assert snapshot(router) == before
    assert_forward(router, entry, raw)
