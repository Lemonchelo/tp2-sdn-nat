"""Especificación ejecutable de ArpTable (hito M2).

Mientras el módulo no esté implementado los tests figuran como xfail (esperado).
Cuando lo implementen deben pasar a XPASS/PASS; al terminar, borrar la línea `pytestmark`
para que cualquier regresión falle de verdad.
"""

import pytest
from pox.lib.addresses import EthAddr, IPAddr

from natsdn.arp_table import ArpTable

pytestmark = pytest.mark.xfail(raises=NotImplementedError, reason="M2 pendiente")

IP = IPAddr("192.168.1.2")
MAC = EthAddr("00:00:00:00:00:02")


def test_learn_and_lookup(clock):
    t = ArpTable(ttl=300, clock=clock)
    t.learn(IP, MAC, port=2)
    e = t.lookup(IP)
    assert e is not None and e.mac == MAC and e.port == 2


def test_lookup_unknown_returns_none(clock):
    assert ArpTable(ttl=300, clock=clock).lookup(IP) is None


def test_entry_expires_after_ttl(clock):
    t = ArpTable(ttl=10, clock=clock)
    t.learn(IP, MAC, port=2)
    clock.advance(11)
    assert t.lookup(IP) is None


def test_learn_refreshes_and_overwrites(clock):
    t = ArpTable(ttl=10, clock=clock)
    t.learn(IP, MAC, port=2)
    clock.advance(8)
    t.learn(IP, EthAddr("00:00:00:00:00:99"), port=3)   # el host cambió de MAC y de puerto
    clock.advance(8)                                    # 16s desde el 1ro, 8s desde el refresh
    e = t.lookup(IP)
    assert e is not None and e.mac == EthAddr("00:00:00:00:00:99") and e.port == 3


def test_expire_returns_count(clock):
    t = ArpTable(ttl=10, clock=clock)
    t.learn(IP, MAC, port=2)
    t.learn(IPAddr("192.168.1.3"), EthAddr("00:00:00:00:00:03"), port=3)
    clock.advance(11)
    assert t.expire() == 2
