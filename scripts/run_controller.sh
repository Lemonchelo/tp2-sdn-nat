#!/usr/bin/env bash
# Arranca el controlador POX con el paquete natsdn (sin copiar nada a pox/ext).
# Uso: ./scripts/run_controller.sh [opciones globales de POX, ej: --no-cli]
# Terminal 1: correr esto primero; Terminal 2: ./scripts/run_topo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
POX_DIR="${POX_DIR:-./pox}"
CONFIG="${CONFIG:-config/network.json}"

# PYTHONPATH = raíz del repo => `natsdn` se importa como paquete desde POX
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" \
  python3 "$POX_DIR/pox.py" log.level --DEBUG "$@" natsdn --config="$CONFIG"
