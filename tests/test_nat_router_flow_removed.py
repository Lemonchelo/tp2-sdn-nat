"""Ciclo de vida NAT ante eventos FlowRemoved reales de POX, sin switch."""

from dataclasses import asdict, replace
from unittest.mock import Mock, patch

import pytest
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.openflow import FlowRemoved

from natsdn.arp_handler import ArpHandler
from natsdn.config import load_config
from natsdn.flow_installer import FlowInstaller
from natsdn.nat_router import NatRouter
from natsdn.nat_table import Direction


EXPIRATIONS = [of.OFPRR_IDLE_TIMEOUT, of.OFPRR_HARD_TIMEOUT]


@pytest.fixture
def router(clock, caplog):
    cfg = replace(load_config(), port_min=50000, port_max=50001)
    router = NatRouter(Mock(), cfg)
    router.nat_table.clock = clock
    router.arp = Mock(spec=ArpHandler)
    caplog.set_level("DEBUG", logger="natsdn")
    yield router
    # Ni packet_out, ni flow_mod, ni consultas ARP durante estos eventos.
    router.connection.send.assert_not_called()
    assert router.arp.mock_calls == []


def seed(router, proto, priv_port=50000):
    entry = router.nat_table.get_or_create_outbound(
        proto, IPAddr("192.168.1.2"), priv_port, 2, IPAddr("200.0.0.1"), 443)
    assert entry is not None
    for direction in Direction:
        router.nat_table.mark_flow_installed(entry, direction)
    return entry


def event_for(router, entry_id, direction, reason):
    message = of.ofp_flow_removed(
        cookie=FlowInstaller.make_cookie(entry_id, direction), reason=reason)
    return FlowRemoved(router.connection, message)


def snapshot(router):
    table = router.nat_table
    pool = table.port_pool
    return ([asdict(entry) for entry in table.entries()],
            [(pool.available(proto), [pool.in_use(proto, port)
                                      for port in (50000, 50001)])
             for proto in (6, 17)])


def assert_live(router, entry):
    table = router.nat_table
    assert entry in list(table.entries())  # índice saliente, API pública
    assert table.get_by_id(entry.entry_id) is entry
    assert table.lookup_inbound(entry.proto, entry.public_port) is entry
    assert table.port_pool.in_use(entry.proto, entry.public_port)


def assert_result_log(caplog, entry_id, direction, released):
    message = (f"FlowRemoved: mapeo {entry_id} sentido {direction.name} "
               + ("liberado" if released else "conservado (otro sentido activo)"))
    assert caplog.messages[-1] == message


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("first_reason", EXPIRATIONS)
@pytest.mark.parametrize("second_reason", EXPIRATIONS)
@pytest.mark.parametrize("first", list(Direction))
def test_release_only_after_both_directions_expire(
        router, clock, caplog, proto, first_reason, second_reason, first):
    entry = seed(router, proto)
    sibling = seed(router, 17 if proto == 6 else 6)
    sibling_before = asdict(sibling)
    last_seen = entry.last_seen
    second = Direction.INBOUND if first == Direction.OUTBOUND else Direction.OUTBOUND
    pool_before = snapshot(router)[1]
    clock.advance(30)

    assert router._handle_FlowRemoved(
        event_for(router, entry.entry_id, first, first_reason)) is None
    assert_live(router, entry)
    assert entry.flow_active == {first: False, second: True}
    assert entry.last_seen == last_seen
    assert snapshot(router)[1] == pool_before
    assert_result_log(caplog, entry.entry_id, first, released=False)

    assert router._handle_FlowRemoved(
        event_for(router, entry.entry_id, second, second_reason)) is None
    assert entry.flow_active == {first: False, second: False}
    assert entry.last_seen == last_seen
    assert router.nat_table.get_by_id(entry.entry_id) is None
    assert router.nat_table.lookup_inbound(proto, entry.public_port) is None
    assert list(router.nat_table.entries()) == [sibling]
    assert not router.nat_table.port_pool.in_use(proto, entry.public_port)
    assert router.nat_table.port_pool.available(proto) == 2
    assert asdict(sibling) == sibling_before
    assert_result_log(caplog, entry.entry_id, second, released=True)
    assert len(caplog.messages) == 2

    # La misma 5-tupla debe crear otro mapeo y reutilizar el puerto liberado.
    replacement = seed(router, proto)
    assert replacement.entry_id == sibling.entry_id + 1
    assert replacement is not entry
    assert replacement.public_port == entry.public_port
    assert_live(router, replacement)


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("reason", [of.OFPRR_DELETE, 3, 255])
@pytest.mark.parametrize("direction", list(Direction))
def test_non_expiry_is_ignored_before_cookie_decoding(
        router, clock, caplog, proto, reason, direction):
    entry = seed(router, proto)
    event = event_for(router, entry.entry_id, direction, reason)
    before = snapshot(router)
    clock.advance(30)
    with patch.object(FlowInstaller, "parse_cookie", wraps=FlowInstaller.parse_cookie) as parse:
        assert router._handle_FlowRemoved(event) is None
        parse.assert_not_called()
    assert snapshot(router) == before
    assert_live(router, entry)
    assert caplog.messages == []
    following = seed(router, proto, priv_port=50001)
    assert following.entry_id == entry.entry_id + 1
    assert following.public_port == 50001


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("reason", EXPIRATIONS)
@pytest.mark.parametrize("direction", list(Direction))
@pytest.mark.parametrize("unknown_id", [0, 99999])
def test_unknown_mapping_is_debug_drop(
        router, clock, caplog, proto, reason, direction, unknown_id):
    entry = seed(router, proto)
    before = snapshot(router)
    clock.advance(30)
    assert router._handle_FlowRemoved(
        event_for(router, unknown_id, direction, reason)) is None
    assert snapshot(router) == before
    assert_live(router, entry)
    assert caplog.record_tuples == [(
        "natsdn", 10,
        f"FlowRemoved ignorado: mapeo {unknown_id} sentido {direction.name} "
        "desconocido o ya liberado",
    )]
    following = seed(router, proto, priv_port=50001)
    assert following.entry_id == entry.entry_id + 1
    assert following.public_port == 50001


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("reason", EXPIRATIONS)
@pytest.mark.parametrize("direction", list(Direction))
def test_duplicate_expiry_keeps_opposite_direction_active(
        router, clock, caplog, proto, reason, direction):
    entry = seed(router, proto)
    event = event_for(router, entry.entry_id, direction, reason)
    router._handle_FlowRemoved(event)
    before = snapshot(router)
    clock.advance(30)
    assert router._handle_FlowRemoved(event) is None
    assert snapshot(router) == before
    assert_live(router, entry)
    opposite = Direction.INBOUND if direction == Direction.OUTBOUND else Direction.OUTBOUND
    assert entry.flow_active == {direction: False, opposite: True}
    assert_result_log(caplog, entry.entry_id, direction, released=False)


@pytest.mark.parametrize("proto", [6, 17])
@pytest.mark.parametrize("reason", EXPIRATIONS)
@pytest.mark.parametrize("direction", list(Direction))
@pytest.mark.parametrize("replaced", [False, True])
def test_late_cookie_after_release_cannot_affect_replacement(
        router, clock, caplog, proto, reason, direction, replaced):
    entry = seed(router, proto)
    late_event = event_for(router, entry.entry_id, direction, reason)
    router.nat_table.release(entry)
    replacement = seed(router, proto) if replaced else None
    if replacement is not None:
        assert replacement.public_port == entry.public_port
        assert replacement.entry_id != entry.entry_id
    before = snapshot(router)
    old_before = asdict(entry)
    clock.advance(30)
    assert router._handle_FlowRemoved(late_event) is None
    assert snapshot(router) == before
    assert asdict(entry) == old_before
    assert router.nat_table.get_by_id(entry.entry_id) is None
    assert caplog.record_tuples == [(
        "natsdn", 10,
        f"FlowRemoved ignorado: mapeo {entry.entry_id} sentido {direction.name} "
        "desconocido o ya liberado",
    )]
    if replacement is not None:
        assert_live(router, replacement)
    else:
        assert router.nat_table.lookup_inbound(proto, entry.public_port) is None
        assert router.nat_table.port_pool.available(proto) == 2
