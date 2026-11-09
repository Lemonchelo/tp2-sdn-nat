# Bitácora

Una línea por decisión o problema (fecha · quién · qué pasó · cómo se resolvió). Alimenta las secciones
“Decisiones de diseño” y “Problemas encontrados” del informe.

- Ale - en ArpHandler.handle_arp se evita cargar en la tabla(aprender) los ARP Probe que vienen con ip 0.0.0.0 (RFC 5227)
- Ale - se ajusta los puerto a privados ante un ARP con OFPP_FLOOD en send_arp_request , para no enviar por la interfaz del switch publico preguntando por el arp. Se ajustó switch_io.py para agregar el property de devolver los puertos fisicos de las interfaces
- Ale - cola de espera en resolve(): Múltiples paquetes salientes hacia un mismo destino sin MAC conocida podrían saturar la red con ARP Requests idénticos. Se diseñó la estructura _PendingResolution para que las solicitudes concurrentes solo agreguen sus callbacks a la cola existente sin reemitir paquetes, manejando los reintentos mediante Timer de POX.
