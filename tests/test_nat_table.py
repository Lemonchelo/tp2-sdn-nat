"""Especificación ejecutable de NatTable (hito M3). Ver nota en test_arp_table.py."""

import pytest
from pox.lib.addresses import IPAddr

from natsdn.config import PROTO_TCP, PROTO_UDP
from natsdn.nat_table import Direction, NatTable
from natsdn.port_pool import PortPool

pytestmark = pytest.mark.xfail(raises=NotImplementedError, reason="M3 pendiente")

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
