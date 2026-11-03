"""Helpers de logging (tomados tal cual del protorouter.py de la cátedra)."""

import logging

# logging estándar: funciona dentro de POX (que lo configura) y en tests sin POX corriendo
log = logging.getLogger("natsdn")

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")
