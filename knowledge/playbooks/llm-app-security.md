---
id: pb-llm-app
kind: playbook
title: "Seguridad de aplicaciones con LLM (targets de IA)"
tags: [ai, llm, prompt-injection, rag, owasp-llm, agents]
refs: [OWASP-LLM-Top10:2025, OWASP-LLM01, OWASP-LLM02, OWASP-LLM06]
severity_hint: high
program: null
---

# Seguridad de aplicaciones con LLM

> Relevante para programas de productos de IA (p.ej. el bug bounty de OpenAI en Bugcrowd).
> Recuerda: los programas suelen pedir que los problemas de *seguridad del modelo* se envíen
> por un canal aparte; el bug bounty premia **impacto de seguridad concreto**, no jailbreaks
> por sí solos.

## Dónde está el valor real
El pago no está en "hacer que diga algo malo", sino en cuando la manipulación del modelo
produce un **impacto de seguridad tradicional**: acceso no autorizado, exfiltración de datos,
ejecución de acciones en nombre de otro, o compromiso de un sistema conectado.

## Clases a evaluar (nivel metodología)

### Inyección de prompt indirecta (LLM01)
Contenido no confiable (una página, un documento, un correo) que el modelo procesa y que
altera su comportamiento. El caso de alto impacto: cuando el agente tiene **herramientas o
conectores** y el contenido logra que ejecute una acción no autorizada o filtre contexto.
Evaluar: ¿de dónde viene el contenido que entra al contexto? ¿puede un tercero inyectarlo?

### Exfiltración vía herramientas/conectores (LLM06 / fuga de datos)
Agentes con acceso a datos (archivos, correo, APIs internas) que pueden ser inducidos a sacar
esos datos hacia un destino controlable. Mapear el grafo de datos que el agente puede tocar y
los canales de salida disponibles.

### Fallas de autorización en el plano de herramientas
El modelo delega en herramientas que no re-verifican permisos: el agente actúa con privilegios
que el usuario final no tiene. Aquí se cruza con IDOR/BOLA (ver `pb-idor`) pero mediado por el
LLM. Suele ser el bug de mayor pago en productos agénticos.

### Superficie clásica alrededor del LLM
El endpoint, el RAG store, los plugins y la cola de trabajos son software normal: aplican SSRF
(`pb-ssrf`), IDOR, inyección y problemas de infraestructura como siempre.

## Cómo se detecta
1. Mapear la arquitectura: ¿qué herramientas/conectores tiene el agente? ¿qué datos alcanza?
   ¿qué contenido no confiable entra a su contexto?
2. Buscar el punto donde una entrada controlable se convierte en una **acción con efecto** o
   en **acceso a datos ajenos**.
3. Confirmar el impacto concreto (no la mera desviación de comportamiento).

## Cómo se evidencia
- Cadena reproducible: entrada → comportamiento del agente → impacto medible (dato ajeno
  obtenido, acción no autorizada ejecutada).
- `EvidenceItem`: `{ vulnerability: "llm-tool-exfil"|"indirect-prompt-injection"|..., host, data_reached, action_taken }`.

## Límites
No perseguir jailbreaks de contenido como finding de bounty salvo que el programa lo pida.
Enviar los problemas de seguridad del modelo por el canal que indique el programa. Mantenerse
dentro del scope de datos y acciones autorizadas.

## Conexión con Hive
Todo lo aprendido aquí se valida después contra el modelo de amenazas de **hive-connect** y los
agentes de **Hive**: el mismo grafo de herramientas/datos/salidas es el que hay que endurecer.
