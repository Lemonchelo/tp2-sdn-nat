"""Especificación ejecutable de PortPool (hito M3). Ver nota en test_arp_table.py."""

import pytest

from natsdn.config import PROTO_TCP, PROTO_UDP
from natsdn.port_pool import PortPool

pytestmark = pytest.mark.xfail(raises=NotImplementedError, reason="M3 pendiente")


def test_allocates_within_range():
    p = PortPool(100, 110)
    assert 100 <= p.allocate(PROTO_TCP) <= 110


def test_preferred_port_is_kept_when_free():
    assert PortPool(100, 110).allocate(PROTO_TCP, preferred=105) == 105


def test_preferred_port_out_of_range_or_busy_gets_another():
    p = PortPool(100, 110)
    assert p.allocate(PROTO_TCP, preferred=105) == 105
    other = p.allocate(PROTO_TCP, preferred=105)         # ocupado
    assert other != 105 and 100 <= other <= 110
    assert 100 <= p.allocate(PROTO_TCP, preferred=5000) <= 110   # fuera de rango


def test_no_duplicates_until_exhausted_then_none():
    p = PortPool(100, 102)                               # 3 puertos
    got = {p.allocate(PROTO_UDP) for _ in range(3)}
    assert got == {100, 101, 102}
    assert p.allocate(PROTO_UDP) is None
    assert p.available(PROTO_UDP) == 0


def test_release_makes_port_available_again():
    p = PortPool(100, 100)
    port = p.allocate(PROTO_TCP)
    assert p.allocate(PROTO_TCP) is None
    p.release(PROTO_TCP, port)
    assert p.allocate(PROTO_TCP) == port


def test_protocols_are_independent():
    p = PortPool(100, 100)
    assert p.allocate(PROTO_TCP) == 100
    assert p.allocate(PROTO_UDP) == 100                  # mismo número, otro protocolo


def test_release_unknown_port_does_not_raise():
    PortPool(100, 110).release(PROTO_TCP, 105)
