#!/usr/bin/env bash
# Clona POX dentro del repo (carpeta ./pox, ignorada por git) para que todos usen lo mismo.
# Uso: ./scripts/setup.sh            (rama por defecto de noxrepo/pox)
#      POX_BRANCH=<rama> ./scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -d pox ]; then
  echo "pox/ ya existe, no hago nada."
  exit 0
fi

BRANCH_ARG=()
if [ -n "${POX_BRANCH:-}" ]; then BRANCH_ARG=(--branch "$POX_BRANCH"); fi
git clone "${BRANCH_ARG[@]}" https://github.com/noxrepo/pox.git pox
echo "Listo. Mininet se instala aparte (apt install mininet)."
