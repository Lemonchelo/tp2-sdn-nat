"""Tests de config.py (hito M1). Usan el network.json real del repo + variantes mínimas."""

import copy
import json
import os

import pytest
from pox.lib.addresses import EthAddr, IPAddr

from natsdn.config import PROTO_ICMP, PROTO_TCP, PROTO_UDP, load_config

REAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "config", "network.json")


def write(tmp_path, mutate=lambda d: None):
    with open(REAL) as f:
        d = json.load(f)
    mutate(d)
    p = tmp_path / "net.json"
    p.write_text(json.dumps(d))
    return str(p)


def test_loads_real_config():
    c = load_config(REAL)
    assert c.public.ip == IPAddr("200.0.0.254") and c.public.port == 1
    assert c.private.mac == EthAddr("00:00:00:bb:bb:bb") and c.private.prefix_len == 24
    assert (c.port_min, c.port_max) == (49152, 65535)


def test_ip_helpers():
    c = load_config(REAL)
    assert c.is_private_ip(IPAddr("192.168.1.7")) and not c.is_private_ip(IPAddr("200.0.0.1"))
    assert c.is_public_ip(IPAddr("200.0.0.1")) and not c.is_public_ip(IPAddr("192.168.1.7"))
    assert c.is_router_ip(IPAddr("192.168.1.254")) and c.is_router_ip(IPAddr("200.0.0.254"))
    assert not c.is_router_ip(IPAddr("192.168.1.2"))


def test_idle_timeout_for():
    c = load_config(REAL)
    assert c.idle_timeout_for(PROTO_TCP) == 120
    assert c.idle_timeout_for(PROTO_UDP) == 30
    assert c.idle_timeout_for(PROTO_ICMP) == 10
    with pytest.raises(ValueError):
        c.idle_timeout_for(99)


def test_controller_ignores_topology_section(tmp_path):
    c = load_config(write(tmp_path, lambda d: d.pop("topology")))
    assert c.public.ip == IPAddr("200.0.0.254")


def test_changing_ips_needs_no_code_change(tmp_path):
    def mut(d):
        d["router"]["private"].update(ip="10.0.0.254", subnet="10.0.0.0/24")
    c = load_config(write(tmp_path, mut))
    assert c.is_private_ip(IPAddr("10.0.0.5")) and c.is_router_ip(IPAddr("10.0.0.254"))


@pytest.mark.parametrize("mutate", [
    lambda d: d["router"]["public"].pop("port"),
    lambda d: d["nat"].update(port_range=[60000, 50000]),
    lambda d: d["router"]["private"].update(subnet="200.0.0.0/24", ip="200.0.0.5"),
    lambda d: d["router"]["private"].update(ip="10.9.9.9"),
])
def test_invalid_configs_raise_value_error(tmp_path, mutate):
    with pytest.raises(ValueError):
        load_config(write(tmp_path, mutate))


def test_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        load_config(str(tmp_path / "nope.json"))
