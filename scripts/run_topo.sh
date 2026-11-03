#!/usr/bin/env bash
# Levanta la topología Mininet (requiere sudo). Correr DESPUÉS del controlador.
set -euo pipefail
cd "$(dirname "$0")/.."
sudo python3 topo/topo.py "${CONFIG:-config/network.json}"
