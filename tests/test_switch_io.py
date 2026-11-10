"""SwitchIO con mensajes POX reales; sin Mininet ni conexión a un switch."""

from copy import deepcopy
from unittest.mock import Mock, call

import pytest
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr

from natsdn.config import Interface, NatConfig, PROTO_TCP, PROTO_UDP
from natsdn.flow_installer import FlowInstaller
from natsdn.nat_table import NatEntry
from natsdn.switch_io import SwitchIO


@pytest.fixture
def connection():
    return Mock(spec=["send"])


@pytest.fixture
def match():
    return of.ofp_match(
        in_port=9, dl_type=0x0800, nw_proto=PROTO_TCP,
        nw_src=IPAddr("10.20.0.23"), nw_dst=IPAddr("203.0.113.42"),
        tp_src=12345, tp_dst=443,
    )


@pytest.fixture
def actions():
    return [
        of.ofp_action_nw_addr.set_src(IPAddr("198.51.100.254")),
        of.ofp_action_tp_port.set_src(54321),
        of.ofp_action_output(port=7),
    ]


def roundtrip(message):
    wire = message.pack()
    decoded = type(message)()
    assert len(wire) == len(message)
    assert decoded.unpack(wire) == (len(wire), len(wire))
    return decoded


def wire_actions(actions):
    expected = deepcopy(actions)
    # POX normaliza max_len al serializar outputs a puertos físicos.
    for action in expected:
        if isinstance(action, of.ofp_action_output) and action.port <= of.OFPP_MAX:
            action.max_len = 0
    return expected


def assert_flow(message, match, actions, *, command=of.OFPFC_ADD,
                idle_timeout=0, hard_timeout=0, priority=of.OFP_DEFAULT_PRIORITY,
                cookie=0, flags=0):
    assert type(message) is of.ofp_flow_mod
    assert message.actions == actions
    expected_actions = wire_actions(actions)
    decoded = roundtrip(message)
    assert decoded.actions == expected_actions
    for candidate in (message, decoded):
        assert candidate.command == command
        assert candidate.match == match
        assert candidate.match.wildcards == match.wildcards
        assert candidate.idle_timeout == idle_timeout
        assert candidate.hard_timeout == hard_timeout
        assert candidate.priority == priority
        assert candidate.cookie == cookie
        assert candidate.flags == flags
        assert candidate.buffer_id is None
        assert candidate.out_port == of.OFPP_NONE


@pytest.mark.parametrize("in_port", [None, 9], ids=["default", "explicit"])
def test_send_packet_payload_port_actions_and_single_send(connection, actions, in_port):
    payload = bytes.fromhex("0200000000010200000000020800") + bytes(range(46))
    kwargs = {} if in_port is None else {"in_port": in_port}
    assert SwitchIO(connection).send_packet(payload, tuple(actions), **kwargs) is None
    message = connection.send.call_args.args[0]
    assert connection.mock_calls == [call.send(message)]
    assert type(message) is of.ofp_packet_out
    assert message.actions == actions
    assert type(message.actions) is list
    expected_actions = wire_actions(actions)
    decoded = roundtrip(message)
    assert decoded.actions == expected_actions
    for candidate in (message, decoded):
        assert candidate.data == payload
        assert candidate.in_port == (of.OFPP_NONE if in_port is None else in_port)
        assert candidate.buffer_id is None


@pytest.mark.parametrize("send_removed", [None, True, False],
                         ids=["default", "enabled", "disabled"])
def test_install_flow_exact_fields_and_removed_flag(connection, match, actions, send_removed):
    kwargs = {} if send_removed is None else {"send_flow_removed": send_removed}
    assert SwitchIO(connection).install_flow(
        match, actions, idle_timeout=81, priority=321,
        cookie=0x123456789ABCDEF0, hard_timeout=123, **kwargs,
    ) is None
    message = connection.send.call_args.args[0]
    assert connection.mock_calls == [call.send(message)]
    assert_flow(
        message, match, actions, idle_timeout=81, hard_timeout=123,
        priority=321, cookie=0x123456789ABCDEF0,
        flags=0 if send_removed is False else of.OFPFF_SEND_FLOW_REM,
    )


def test_install_flow_optional_defaults(connection, match, actions):
    assert SwitchIO(connection).install_flow(match, actions, 19, 321) is None
    message = connection.send.call_args.args[0]
    assert connection.mock_calls == [call.send(message)]
    assert_flow(message, match, actions, idle_timeout=19, priority=321,
                flags=of.OFPFF_SEND_FLOW_REM)


@pytest.mark.parametrize("priority", [None, 321], ids=["default", "explicit"])
def test_delete_flow_strict_exact_match_and_priority(connection, match, priority):
    kwargs = {} if priority is None else {"priority": priority}
    assert SwitchIO(connection).delete_flow(match, **kwargs) is None
    message = connection.send.call_args.args[0]
    assert connection.mock_calls == [call.send(message)]
    assert_flow(message, match, [], command=of.OFPFC_DELETE_STRICT,
                priority=of.OFP_DEFAULT_PRIORITY if priority is None else priority)


@pytest.mark.parametrize("ports, expected", [
    (None, []),
    ({}, []),
    # Se conserva el filtro <= OFPP_MAX y el orden del mapa existente.
    ({of.OFPP_CONTROLLER: object(), of.OFPP_MAX: object(), 1: object(),
      of.OFPP_MAX + 1: object(), of.OFPP_MAX - 1: object(),
      of.OFPP_LOCAL: object(), of.OFPP_NONE: object()},
     [of.OFPP_MAX, 1, of.OFPP_MAX - 1]),
], ids=["missing", "empty", "physical-and-reserved-boundaries"])
def test_physical_ports_preserves_existing_filter(connection, ports, expected):
    if ports is not None:
        connection.ports = ports
    assert SwitchIO(connection).physical_ports == expected
    assert connection.mock_calls == []


@pytest.mark.parametrize("proto, timeout", [(PROTO_TCP, 81), (PROTO_UDP, 19)],
                         ids=["tcp", "udp"])
def test_flow_installer_through_switch_io_install_and_delete(connection, proto, timeout):
    cfg = NatConfig(
        public=Interface(IPAddr("198.51.100.254"), EthAddr("02:00:00:00:07:01"),
                         IPAddr("198.51.100.0"), 24, port=7),
        private=Interface(IPAddr("10.20.0.254"), EthAddr("02:00:00:00:09:01"),
                          IPAddr("10.20.0.0"), 24),
        tcp_idle_timeout=81, udp_idle_timeout=19, flow_priority=321,
    )
    entry = NatEntry(
        entry_id=37, proto=proto, priv_ip=IPAddr("10.20.0.23"),
        priv_port=12345, priv_switch_port=9, remote_ip=IPAddr("203.0.113.42"),
        remote_port=443, public_port=54321, created_at=1.0, last_seen=2.0,
    )
    host_mac = EthAddr("02:00:00:00:00:23")
    installer = FlowInstaller(cfg, SwitchIO(connection))
    outbound = installer.install_outbound(entry, host_mac)
    inbound = installer.install_inbound(entry, host_mac)
    assert connection.send.call_count == 2
    assert installer.remove_flows(entry) is None
    messages = [c.args[0] for c in connection.send.call_args_list]
    assert len(messages) == 4
    assert connection.mock_calls == [call.send(message) for message in messages]
    assert messages[0].actions is outbound
    assert messages[1].actions is inbound

    matches = [
        of.ofp_match(in_port=9, dl_type=0x0800, nw_proto=proto,
                     nw_src=entry.priv_ip, tp_src=12345,
                     nw_dst=entry.remote_ip, tp_dst=443),
        of.ofp_match(in_port=7, dl_type=0x0800, nw_proto=proto,
                     nw_src=entry.remote_ip, tp_src=443,
                     nw_dst=cfg.public.ip, tp_dst=54321),
    ]
    expected_actions = [
        [of.ofp_action_dl_addr.set_src(cfg.public.mac),
         of.ofp_action_dl_addr.set_dst(host_mac),
         of.ofp_action_nw_addr.set_src(cfg.public.ip),
         of.ofp_action_tp_port.set_src(54321), of.ofp_action_output(port=7)],
        [of.ofp_action_dl_addr.set_src(cfg.private.mac),
         of.ofp_action_dl_addr.set_dst(host_mac),
         of.ofp_action_nw_addr.set_dst(entry.priv_ip),
         of.ofp_action_tp_port.set_dst(12345), of.ofp_action_output(port=9)],
    ]
    for index in (0, 1):
        assert_flow(messages[index], matches[index], expected_actions[index],
                    idle_timeout=timeout, priority=321, cookie=(37 << 1) | index,
                    flags=of.OFPFF_SEND_FLOW_REM)
    for message, match in zip(messages[2:], reversed(matches)):
        assert_flow(message, match, [], command=of.OFPFC_DELETE_STRICT, priority=321)
