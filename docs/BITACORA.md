# Bitácora

Una línea por decisión o problema (fecha · quién · qué pasó · cómo se resolvió). Alimenta las secciones
“Decisiones de diseño” y “Problemas encontrados” del informe.

- Ale - en ArpHandler.handle_arp se evita cargar en la tabla(aprender) los ARP Probe que vienen con ip 0.0.0.0 (RFC 5227)
- Ale - se ajusta los puerto a privados ante un ARP con OFPP_FLOOD en send_arp_request , para no enviar por la interfaz del switch publico preguntando por el arp. Se ajustó switch_io.py para agregar el property de devolver los puertos fisicos de las interfaces
- Ale - cola de espera en resolve(): Múltiples paquetes salientes hacia un mismo destino sin MAC conocida podrían saturar la red con ARP Requests idénticos. Se diseñó la estructura _PendingResolution para que las solicitudes concurrentes solo agreguen sus callbacks a la cola existente sin reemitir paquetes, manejando los reintentos mediante Timer de POX.

- 2026-11-10 · Diego · El orden original de `classify_ip` clasificaba las respuestas NAT como `TO_ROUTER`, haciendo inalcanzable `INBOUND` · Se priorizó el ingreso por el puerto público hacia la IP pública del router, antes de evaluar otras direcciones propias.
- 2026-11-10 · Diego · La salida NAT podía necesitar resolver las MAC pública y privada antes de reenviar · `handle_outbound` espera ambas resoluciones antes de instalar los dos flujos y reutiliza las mismas acciones salientes para enviar los bytes originales del primer paquete.
- 2026-11-10 · Diego · Los callbacks ARP diferidos podían actuar sobre un mapeo liberado o interferir con otro paquete de la misma conexión · Se validó la identidad del mapeo y se limitó cada invocación a un reenvío; un fallo saliente libera solo su mapeo recién creado si sigue vigente y no tiene flujos activos, sin borrar uno previo o activado por otro paquete.
