"""Extracción pública de transporte con paquetes POX reales."""

import pytest
from pox.lib.packet.icmp import icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

from natsdn.packet_utils import TransportInfo, extract_transport


@pytest.mark.parametrize("transport,proto", [(tcp, 6), (udp, 17)])
@pytest.mark.parametrize("src,dst", [(12345, 443), (0, 65535)])
def test_extract_parsed_transport(transport, proto, src, dst):
    packet = ipv4(protocol=proto, payload=transport(srcport=src, dstport=dst))
    packet = ipv4(raw=packet.pack())
    assert extract_transport(packet) == TransportInfo(proto, src, dst)


@pytest.mark.parametrize("transport,proto", [(tcp, 6), (udp, 17)])
@pytest.mark.parametrize("case", ["unparsed", "truncated", "fragment", "last_fragment", "initial_fragment"])
def test_extract_transport_rejects_missing_headers(transport, proto, case):
    packet = ipv4(protocol=proto, payload=transport(srcport=12345, dstport=80))
    packet = ipv4(raw=packet.pack())
    if case == "unparsed":
        packet.payload.parsed = False
    elif case == "truncated":
        packet.payload = b"\x01"
        packet = ipv4(raw=packet.pack())
    elif case in ("fragment", "last_fragment"):
        packet.frag = 1 if case == "fragment" else 8191
    else:
        packet.flags = ipv4.MF_FLAG
    expected = TransportInfo(proto, 12345, 80) if case == "initial_fragment" else None
    assert extract_transport(packet) == expected


@pytest.mark.parametrize("proto,payload", [(1, icmp()), (99, b"unsupported")])
def test_extract_unsupported_transport(proto, payload):
    packet = ipv4(raw=ipv4(protocol=proto, payload=payload).pack())
    assert extract_transport(packet) is None
