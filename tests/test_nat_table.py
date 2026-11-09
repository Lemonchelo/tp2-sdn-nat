"""Especificación ejecutable de NatTable (hito M3). Ver nota en test_arp_table.py."""

import pytest
from pox.lib.addresses import IPAddr

from natsdn.config import PROTO_TCP, PROTO_UDP
from natsdn.nat_table import Direction, NatTable
from natsdn.port_pool import PortPool

H2, H3 = IPAddr("192.168.1.2"), IPAddr("192.168.1.3")
SRV = IPAddr("200.0.0.1")


def make(clock, lo=5000, hi=5010):
    return NatTable(PortPool(lo, hi), clock=clock)


def test_outbound_creates_entry_with_public_port(clock):
    t = make(clock)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    assert e is not None and 5000 <= e.public_port <= 5010
    assert (e.priv_ip, e.priv_port, e.remote_ip, e.remote_port) == (H2, 40000, SRV, 80)


def test_same_connection_is_idempotent(clock):
    t = make(clock)
    a = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    b = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    assert a is b and t.port_pool.available(PROTO_TCP) == 10


def test_two_hosts_same_source_port_do_not_collide(clock):
    t = make(clock)
    a = t.get_or_create_outbound(PROTO_UDP, H2, 5000, 2, SRV, 53)
    b = t.get_or_create_outbound(PROTO_UDP, H3, 5000, 3, SRV, 53)
    assert a.public_port != b.public_port


def test_lookup_inbound(clock):
    t = make(clock)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    assert t.lookup_inbound(PROTO_TCP, e.public_port) is e
    assert t.lookup_inbound(PROTO_UDP, e.public_port) is None   # otro protocolo
    assert t.lookup_inbound(PROTO_TCP, 6000) is None            # sin mapeo


def test_pool_exhaustion_returns_none(clock):
    t = make(clock, 5000, 5001)
    assert t.get_or_create_outbound(PROTO_TCP, H2, 1, 2, SRV, 80) is not None
    assert t.get_or_create_outbound(PROTO_TCP, H2, 2, 2, SRV, 80) is not None
    assert t.get_or_create_outbound(PROTO_TCP, H2, 3, 2, SRV, 80) is None


def test_entry_released_only_when_both_flows_removed(clock):
    t = make(clock)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    t.mark_flow_installed(e, Direction.OUTBOUND)
    t.mark_flow_installed(e, Direction.INBOUND)
    assert t.on_flow_removed(e, Direction.INBOUND) is False
    assert t.lookup_inbound(PROTO_TCP, e.public_port) is e      # sigue viva
    assert t.on_flow_removed(e, Direction.OUTBOUND) is True
    assert t.lookup_inbound(PROTO_TCP, e.public_port) is None
    assert t.port_pool.available(PROTO_TCP) == 11               # el puerto volvió al pool


def test_expire_stale(clock):
    t = make(clock)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    clock.advance(100)
    assert t.expire_stale(max_age=60) == [e]
    assert t.lookup_inbound(PROTO_TCP, e.public_port) is None


def test_idempotence_refreshes_time_even_with_full_pool(clock):
    t = make(clock, 5000, 5000)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 5000, 2, SRV, 80)
    assert e.public_port == 5000
    assert e.created_at == e.last_seen == 0
    assert not any(e.flow_active.values())
    clock.advance(5)
    assert t.get_or_create_outbound(PROTO_TCP, H2, 5000, 2, SRV, 80) is e
    assert e.created_at == 0 and e.last_seen == 5
    assert list(t.entries()) == [e]
    assert t.get_by_id(e.entry_id) is e
    assert t.get_by_id(e.entry_id + 1) is None


def test_protocols_have_independent_entries_and_ports(clock):
    t = make(clock, 5000, 5000)
    tcp = t.get_or_create_outbound(PROTO_TCP, H2, 5000, 2, SRV, 80)
    udp = t.get_or_create_outbound(PROTO_UDP, H2, 5000, 2, SRV, 80)
    assert tcp.public_port == udp.public_port == 5000
    assert tcp.entry_id != udp.entry_id
    t.release(tcp)
    assert t.lookup_inbound(PROTO_UDP, 5000) is udp
    assert t.port_pool.in_use(PROTO_UDP, 5000)


@pytest.mark.parametrize('field,value', [
    ('priv_ip', H3), ('priv_port', 40001),
    ('remote_ip', IPAddr('200.0.0.2')), ('remote_port', 443),
])
def test_each_outbound_tuple_component_distinguishes_connections(clock, field, value):
    t = make(clock)
    args = dict(proto=PROTO_TCP, priv_ip=H2, priv_port=40000,
                priv_switch_port=2, remote_ip=SRV, remote_port=80)
    first = t.get_or_create_outbound(**args)
    args[field] = value
    second = t.get_or_create_outbound(**args)
    assert second is not first
    assert second.public_port != first.public_port
    assert t.lookup_inbound(PROTO_TCP, first.public_port) is first
    assert t.lookup_inbound(PROTO_TCP, second.public_port) is second


def test_release_synchronizes_indices_and_old_reference_is_harmless(clock):
    t = make(clock, 5000, 5000)
    args = (PROTO_TCP, H2, 5000, 2, SRV, 80)
    old = t.get_or_create_outbound(*args)
    t.release(old)
    assert list(t.entries()) == []
    assert t._by_outbound == t._by_inbound == {}
    assert t.get_by_id(old.entry_id) is None
    assert t.lookup_inbound(PROTO_TCP, 5000) is None
    assert t.port_pool.available(PROTO_TCP) == 1
    new = t.get_or_create_outbound(*args)
    assert new.entry_id > old.entry_id
    t.release(old)
    assert t.get_or_create_outbound(*args) is new
    assert t.lookup_inbound(PROTO_TCP, 5000) is new
    assert t.port_pool.available(PROTO_TCP) == 0


@pytest.mark.parametrize('first', list(Direction))
def test_flow_removal_order_duplicates_and_reinstallation(clock, first):
    t = make(clock)
    e = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    other = Direction.INBOUND if first == Direction.OUTBOUND else Direction.OUTBOUND
    clock.advance(5)
    for direction in Direction:
        t.mark_flow_installed(e, direction)
    assert e.last_seen == 5
    assert all(e.flow_active.values())
    assert not t.on_flow_removed(e, first)
    assert not t.on_flow_removed(e, first)
    assert not e.flow_active[first] and e.flow_active[other]
    t.mark_flow_installed(e, first)
    assert not t.on_flow_removed(e, other)
    assert t.on_flow_removed(e, first)
    assert t.get_by_id(e.entry_id) is None
    assert list(t.entries()) == []


def test_expiration_boundary_refresh_and_multiple_entries(clock):
    t = make(clock)
    old = t.get_or_create_outbound(PROTO_TCP, H2, 40000, 2, SRV, 80)
    other = t.get_or_create_outbound(PROTO_UDP, H2, 40000, 2, SRV, 53)
    fresh = t.get_or_create_outbound(PROTO_TCP, H3, 40000, 3, SRV, 80)
    clock.advance(60)
    assert t.expire_stale(60) == []  # La condición especificada es estrictamente >.
    t.mark_flow_installed(fresh, Direction.OUTBOUND)
    clock.advance(1)
    assert t.expire_stale(60) == [old, other]
    assert list(t.entries()) == [fresh]
    for entry in (old, other):
        assert t.get_by_id(entry.entry_id) is None
        assert t.lookup_inbound(entry.proto, entry.public_port) is None
        assert not t.port_pool.in_use(entry.proto, entry.public_port)
    assert t.expire_stale(60) == []
    t.release(fresh)
    assert t.expire_stale(60) == []
