# Plan de pruebas (alimenta la sección “Pruebas realizadas” del informe)

Terminal 1: `./scripts/run_controller.sh` · Terminal 2: `./scripts/run_topo.sh` (CLI de Mininet).
Capturar con `tcpdump -i h1-eth0 -nn` / Wireshark en `s1-eth1` (lado público) para evidencia.

| # | Prueba | Cómo | Resultado esperado |
|---|---|---|---|
| T0 | Sin ARP estático | `h2 arp -n` antes de todo | Vacío; no hay `setARP` en la topología |
| T1 | ARP del gateway | `h2 arping -c1 192.168.1.254` | Responde `00:00:00:bb:bb:bb` |
| T2 | UDP básico | `h1 nc -u -l 5000 &` · `h2 nc -u 200.0.0.1 5000` | Llega; en `h1` se ve origen `200.0.0.254:<puerto pool>` |
| T3 | TCP básico | `h1 python3 -m http.server 80 &` · `h2 curl 200.0.0.1` | Respuesta HTTP OK |
| T4 | Múltiples clientes | `h2`, `h3`, `h4` hacen `curl` a `h1` a la vez | Cada uno recibe su respuesta; puertos públicos distintos |
| T5 | Mismo puerto origen | `h2` y `h3` con el mismo puerto origen (`nc -p 5000`) | Dos mapeos con puertos públicos distintos, sin colisión |
| T6 | Conexiones simultáneas de un host | `h2 iperf -c 200.0.0.1 -P 5` (con `h1 iperf -s`) | 5 mapeos; throughput estable |
| T7 | Controlador fuera del camino | Durante `iperf`, mirar logs del controlador | No hay `PacketIn` después del primer paquete de cada conexión |
| T8 | Flujos instalados | `sh ovs-ofctl dump-flows s1` | 2 flujos por conexión con rewrite de IP/puerto/MAC |
| T9 | Expiración | Cortar tráfico y esperar `idle_timeout`; `dump-flows` + log | Flujos removidos, mapeo liberado, puerto de vuelta al pool |
| T10 | Tráfico no solicitado | `h1 nc 200.0.0.254 49152` sin conexión previa | Descartado (log `NO MAPPING`) |
| T11 | ARP de un destino inexistente | `h2 nc -u 200.0.0.99 5000` | Reintentos de ARP y descarte con log; sin cuelgues |
| T12 | **Demo:** cambiar IPs/MACs | Editar `config/network.json` (router y hosts), reiniciar | Todo sigue funcionando sin tocar código |
| T13 | Agotamiento de pool | `port_range` mínimo (ej. `[50000, 50001]`) + 3 conexiones | La 3ra se descarta con log claro |
| T14 *(opcional)* | Ping | `h2 ping -c3 200.0.0.1` / `h2 ping 192.168.1.254` | Con M5 implementado responde |

Tests unitarios (lógica pura): `pip install -r requirements-dev.txt && pytest -q`.
