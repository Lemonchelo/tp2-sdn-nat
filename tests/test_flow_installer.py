"""Regresiones OpenFlow reales en el límite FlowInstaller/SwitchIO, sin switch."""

from unittest.mock import Mock, call

import pytest
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet

from natsdn.config import Interface, NatConfig, PROTO_TCP, PROTO_UDP
from natsdn.flow_installer import FlowInstaller
from natsdn.nat_table import Direction, NatEntry
from natsdn.switch_io import SwitchIO


@pytest.fixture
def installer():
    cfg = NatConfig(
        public=Interface(IPAddr("198.51.100.254"), EthAddr("02:00:00:00:07:01"),
                         IPAddr("198.51.100.0"), 24, port=7),
        private=Interface(IPAddr("10.20.0.254"), EthAddr("02:00:00:00:09:01"),
                          IPAddr("10.20.0.0"), 24),
        tcp_idle_timeout=81, udp_idle_timeout=19, flow_priority=321,
    )
    return FlowInstaller(cfg, Mock(spec=SwitchIO))


@pytest.fixture(params=[PROTO_TCP, PROTO_UDP], ids=["tcp", "udp"])
def entry(request):
    return NatEntry(
        entry_id=37, proto=request.param, priv_ip=IPAddr("10.20.0.23"),
        priv_port=12345, priv_switch_port=9, remote_ip=IPAddr("203.0.113.42"),
        remote_port=443, public_port=54321, created_at=1.0, last_seen=2.0,
    )


def expected_match(cfg, entry, direction):
    if direction == Direction.OUTBOUND:
        return of.ofp_match(
            in_port=entry.priv_switch_port, dl_type=ethernet.IP_TYPE,
            nw_proto=entry.proto, nw_src=entry.priv_ip, tp_src=entry.priv_port,
            nw_dst=entry.remote_ip, tp_dst=entry.remote_port,
        )
    return of.ofp_match(
        in_port=cfg.public.port, dl_type=ethernet.IP_TYPE,
        nw_proto=entry.proto, nw_src=entry.remote_ip, tp_src=entry.remote_port,
        nw_dst=cfg.public.ip, tp_dst=entry.public_port,
    )


def expected_actions(cfg, entry, direction, host_mac):
    if direction == Direction.OUTBOUND:
        return [
            of.ofp_action_dl_addr.set_src(cfg.public.mac),
            of.ofp_action_dl_addr.set_dst(host_mac),
            of.ofp_action_nw_addr.set_src(cfg.public.ip),
            of.ofp_action_tp_port.set_src(entry.public_port),
            of.ofp_action_output(port=cfg.public.port),
        ]
    return [
        of.ofp_action_dl_addr.set_src(cfg.private.mac),
        of.ofp_action_dl_addr.set_dst(host_mac),
        of.ofp_action_nw_addr.set_dst(entry.priv_ip),
        of.ofp_action_tp_port.set_dst(entry.priv_port),
        of.ofp_action_output(port=entry.priv_switch_port),
    ]


@pytest.mark.parametrize("direction", list(Direction))
def test_build_match_exact_fields_and_wire_roundtrip(installer, entry, direction):
    match = installer.build_match(entry, direction)
    expected = expected_match(installer.cfg, entry, direction)
    assert type(match) is of.ofp_match
    assert match == expected
    assert match.wildcards == expected.wildcards
    assert match.get_nw_src()[1] == match.get_nw_dst()[1] == 32
    wire = match.pack(flow_mod=True)
    decoded = of.ofp_match()
    assert decoded.unpack(wire, flow_mod=True) == len(wire)
    assert decoded == expected
    installer.io.assert_not_called()
    assert installer.io.mock_calls == []


@pytest.mark.parametrize("direction", list(Direction))
def test_build_actions_exact_order_values_and_wire_roundtrip(installer, entry, direction):
    host_mac = EthAddr("02:00:00:00:00:23")
    if direction == Direction.OUTBOUND:
        actions = installer.build_outbound_actions(entry, host_mac)
    else:
        actions = installer.build_inbound_actions(entry, host_mac)
    expected = expected_actions(installer.cfg, entry, direction, host_mac)
    assert [type(action) for action in actions] == [type(action) for action in expected]
    assert [action.type for action in actions] == [action.type for action in expected]
    assert actions == expected
    # Un flow_mod real verifica que POX acepta y decodifica toda la lista ordenada.
    message = of.ofp_flow_mod(
        match=expected_match(installer.cfg, entry, direction), actions=actions,
    )
    wire = message.pack()
    decoded = of.ofp_flow_mod()
    assert decoded.unpack(wire) == (len(wire), len(wire))
    assert decoded.match == message.match
    # POX normaliza max_len a cero al serializar outputs a puertos físicos.
    expected[-1] = of.ofp_action_output(port=expected[-1].port, max_len=0)
    assert decoded.actions == expected
    assert installer.io.mock_calls == []


@pytest.mark.parametrize("direction", list(Direction))
def test_install_passes_exact_arguments_and_returns_same_actions(installer, entry, direction):
    host_mac = EthAddr("02:00:00:00:00:23")
    if direction == Direction.OUTBOUND:
        actions = installer.install_outbound(entry, host_mac)
    else:
        actions = installer.install_inbound(entry, host_mac)
    expected = expected_actions(installer.cfg, entry, direction, host_mac)
    cookie = (entry.entry_id << 1) | int(direction)
    timeout = 81 if entry.proto == PROTO_TCP else 19
    assert installer.io.mock_calls == [call.install_flow(
        expected_match(installer.cfg, entry, direction), expected,
        idle_timeout=timeout, priority=321, cookie=cookie,
    )]
    assert installer.io.install_flow.call_args.args[1] is actions
    assert actions == expected
    assert FlowInstaller.parse_cookie(cookie) == (entry.entry_id, direction)


def test_remove_flows_uses_both_exact_matches_and_priority(installer, entry):
    assert installer.remove_flows(entry) is None
    assert installer.io.mock_calls == [
        call.delete_flow(expected_match(installer.cfg, entry, Direction.INBOUND), priority=321),
        call.delete_flow(expected_match(installer.cfg, entry, Direction.OUTBOUND), priority=321),
    ]


@pytest.mark.parametrize("entry_id", [0, 1, 37, (1 << 63) - 1])
@pytest.mark.parametrize("direction", list(Direction))
def test_cookie_roundtrip_including_64_bit_boundary(entry_id, direction):
    cookie = FlowInstaller.make_cookie(entry_id, direction)
    assert cookie == (entry_id << 1) | int(direction)
    parsed_id, parsed_direction = FlowInstaller.parse_cookie(cookie)
    assert parsed_id == entry_id
    assert parsed_direction is direction
    message = of.ofp_flow_mod(cookie=cookie)
    wire = message.pack()
    decoded = of.ofp_flow_mod()
    assert decoded.unpack(wire) == (len(wire), len(wire))
    assert decoded.cookie == cookie
