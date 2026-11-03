"""natsdn: NAT saliente con PAT sobre SDN (POX + OpenFlow 1.0).

Se arranca con:  python3 pox/pox.py natsdn [--config=config/network.json]
(POX resuelve el nombre `natsdn` y busca `launch()` acá; la implementación vive en nat_router.py.
No usar `natsdn.nat_router`: POX no resuelve bien nombres con puntos fuera de su árbol.)

Ver docs/ARQUITECTURA.md para el diseño y los flujos.
"""

from natsdn.nat_router import launch  # noqa: F401  (entry point para POX)
