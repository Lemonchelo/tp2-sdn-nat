# TP2 – SDN / NAT con POX y Mininet (Redes TA048)

NAT saliente con traducción por puertos (PAT) implementado como aplicación SDN: un switch
OpenFlow 1.0 controlado por POX hace de router con una IP pública compartida.

**Estado: esqueleto.** Las firmas, el flujo y las decisiones de diseño están definidos; el cuerpo
de cada función es `raise NotImplementedError("TODO(Mx): ...")` y su docstring dice **qué hay que
implementar**. Enunciado: [`docs/enunciado_TP2_NAT.pdf`](docs/enunciado_TP2_NAT.pdf).

**Leer primero:** [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) (componentes, flujos, reglas
OpenFlow, decisiones D1–D14, preguntas abiertas).

## Estructura

```
config/network.json    IPs/MACs/puertos/timeouts. Fuente única para topo y controlador
natsdn/                Controlador POX (paquete)
  nat_router.py          orquestador (PacketIn / FlowRemoved) + launch()
  arp_handler.py         responder ARP del router + resolver MACs (cola pendiente)
  arp_table.py           tabla ARP dinámica            (lógica pura)
  nat_table.py           tabla NAT por conexión        (lógica pura)
  port_pool.py           pool de puertos públicos      (lógica pura)
  flow_installer.py      NatEntry -> flujos OpenFlow
  switch_io.py           packet_out / flow_mod
  config.py, packet_utils.py, log_utils.py
topo/topo.py           Topología Mininet (hosts privados configurables)
tests/                 Especificación ejecutable de la lógica pura
docs/                  Arquitectura, plan de pruebas, plantilla de informe
reference/             Código original de la cátedra (protorouter.py, topo_base.py)
scripts/               setup / run_controller / run_topo
```

## Cómo correrlo

```bash
./scripts/setup.sh                 # clona POX en ./pox (ignorado por git)
./scripts/run_controller.sh        # terminal 1
./scripts/run_topo.sh              # terminal 2 (sudo; requiere Mininet)
pip install -r requirements-dev.txt && pytest -q    # tests unitarios
```

El controlador se importa como paquete (`PYTHONPATH` = raíz del repo), no hace falta copiar
nada a `pox/ext/`. Si la cátedra exige tenerlo ahí: `ln -s $PWD/natsdn pox/ext/natsdn`.

## Hitos y reparto sugerido

Cada `TODO(Mx)` del código indica su hito: `grep -rn "TODO(M2)" natsdn/`.

| Hito | Qué | Módulos | Depende de |
|---|---|---|---|
| **M1** | Config + topología con N hosts privados, sin `setARP` | `config.py`, `topo/topo.py` | — |
| **M2** | ARP dinámico (responder + resolver + cola) | `arp_table.py`, `arp_handler.py`, `packet_utils.py` (ARP), `switch_io.send_packet` | M1 |
| **M3** | Tabla NAT + pool de puertos | `port_pool.py`, `nat_table.py` | — (puro, en paralelo con M1/M2) |
| **M4** | Flujos + orquestación (primero UDP, después TCP) | `flow_installer.py`, `switch_io.py`, `nat_router.py`, `packet_utils.extract_transport` | M1–M3 |
| **M5** | Opcionales, pruebas y demo | ICMP/ping, `dump_state`, `docs/PLAN_DE_PRUEBAS.md`, informe | M4 |

Podemos paralelizar así: **A** = M1 · **B** = M2 · **C** = M3 · **D** = M4 · **E** = M5 + informe
(con menos gente se juntan M1+M2 y M3+M4). M2 y M3 son independientes y su lógica pura ya tiene
tests en `tests/`.

## Reglas de trabajo

- **Las firmas son el contrato** entre módulos. Si hay que cambiar una, avisar y actualizar
  `docs/ARQUITECTURA.md`.
- Una rama por hito (`m2-arp`, `m3-nat-table`, ...), PR a `main`, otra persona revisa.
- Los tests de `tests/` están en `xfail` hasta que se implemente el módulo; cuando lo hagan,
  **borren la línea `pytestmark`** de ese archivo para que pase a ser un test real.
- **Prohibido hardcodear** IPs/MACs/puertos: en la demo se cambian (ver prueba T12).
- Evidencias para el informe (capturas, `dump-flows`) → guardarlas apenas se obtienen.
- Decisiones nuevas o problemas encontrados → agregarlos a `docs/BITACORA.md` (alimenta el informe).

## Entrega

Código (topología + controlador) e informe PDF — martes **17/11/2026 19:00 hs**, campus.
Plantilla del informe: [`docs/INFORME_TEMPLATE.md`](docs/INFORME_TEMPLATE.md).
