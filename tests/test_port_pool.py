"""Especificación ejecutable de PortPool (hito M3). Ver nota en test_arp_table.py."""

from natsdn.port_pool import PortPool

# Números de protocolo IP; estas pruebas puras no necesitan importar POX vía config.
PROTO_TCP, PROTO_UDP = 6, 17


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


def test_circular_scan_skips_busy_ports_and_wraps():
    p = PortPool(100, 103)
    assert p.allocate(PROTO_TCP, preferred=102) == 102
    assert p.allocate(PROTO_TCP) == 103
    assert p.allocate(PROTO_TCP) == 100
    p.release(PROTO_TCP, 100)
    assert p.allocate(PROTO_TCP) == 101
    assert p.allocate(PROTO_TCP) == 100
    assert p.allocate(PROTO_TCP) is None


def test_preferred_endpoints_and_reuse():
    p = PortPool(100, 102)
    for port in (100, 102):
        assert p.allocate(PROTO_TCP, preferred=port) == port
        assert p.in_use(PROTO_TCP, port)
        p.release(PROTO_TCP, port)
        assert not p.in_use(PROTO_TCP, port)
        assert p.allocate(PROTO_TCP, preferred=port) == port
    assert p.available(PROTO_TCP) == 1


def test_release_is_protocol_specific_and_warns_when_unknown(caplog):
    p = PortPool(100, 100)
    assert p.available(PROTO_TCP) == p.available(PROTO_UDP) == 1
    assert not p.in_use(PROTO_TCP, 100)
    p.allocate(PROTO_TCP)
    p.allocate(PROTO_UDP)
    p.release(PROTO_TCP, 100)
    p.release(PROTO_TCP, 100)
    p.release(PROTO_UDP, 99)
    assert len(caplog.records) == 2
    assert all(record.levelname == 'WARNING' for record in caplog.records)
    assert p.available(PROTO_TCP) == 1
    assert p.available(PROTO_UDP) == 0
    assert p.in_use(PROTO_UDP, 100)
