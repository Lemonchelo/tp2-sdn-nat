# Informe TP2 – SDN / NAT (plantilla)

> Estructura exigida por el enunciado §7.1. Cada sección indica quién la alimenta desde el repo.
> Entrega: martes 17/11/2026, 19:00 hs, por el campus. PDF.

1. **Descripción general de la solución** — resumen de `docs/ARQUITECTURA.md` §1–§2.
2. **Diseño de la tabla NAT** — §4 de la arquitectura + por qué por conexión (D2–D4).
3. **Manejo de ARP** — tabla ARP, responder por IPs del router, resolución con cola pendiente (D8–D9).
4. **Estrategia de instalación de flujos** — §5 y D5–D7, D12–D13 (timeouts, cookies, FlowRemoved).
5. **Decisiones de diseño** — tabla §6.
6. **Problemas encontrados y soluciones** — *completar durante el desarrollo* (llevar un log en `docs/BITACORA.md`).
7. **Pruebas realizadas** — `docs/PLAN_DE_PRUEBAS.md`: conectividad básica, múltiples clientes, distintos tipos de tráfico. Incluir capturas (Wireshark/tcpdump) y salidas de `dump-flows`.
8. **Conclusión**.

Anexo sugerido: diagrama de secuencia (§3.1) y tabla NAT de ejemplo tomada de una corrida real.
