# INFORME EJECUTIVO FINAL DE CIBERSEGURIDAD

**Proyecto:** hiveApp  
**Repositorio:** `https://github.com/johpaz/hiveAgents` (rama `main`)  
**Aplicación:** Frontend React + Vite, desplegado en Vercel (`hive-web`)  
**Alcance:** Análisis estático de código (SAST), revisión forense de repositorio e inteligencia de amenazas.  
**Fecha del informe:** 2024  
**Clasificación:** CONFIDENCIAL – Uso interno del equipo de seguridad y liderazgo de proyecto.  

---

## 1. RESUMEN EJECUTIVO

El análisis conjunto de los equipos de código, forense e inteligencia de amenazas ha identificado **9 hallazgos** que afectan la confidencialidad, integridad y disponibilidad del proyecto hiveApp. El riesgo más grave y de explotación inmediata es la **exposición de una API Key privada de Google Gemini** (`GEMINI_API_KEY`), la cual se encuentra hardcodeada en el archivo `.env` e **inyectada directamente en el bundle del cliente** mediante la configuración de Vite (`vite.config.ts`). Esto permite que cualquier usuario que acceda a la aplicación web extraiga la clave y abuse de la cuota del proyecto, generando costos imprevistos y daño reputacional.

Adicionalmente, se confirma la exposición de **Información Personal Identificable (PII)** de un fundador (número telefónico colombiano), la ausencia de mecanismos de autenticación y autorización en los endpoints de la hackathon, riesgo potencial de Cross-Site Scripting (XSS) en el componente de chat, y deficiencias en la gobernanza del repositorio Git (secrets trackeados, builds no reproducibles y directorios no auditables).

**Recomendación ejecutiva:** Tratar este informe como una remediación de emergencia (hotfix). La rotación de la API Key y la purga del historial Git deben ejecutarse **inmediatamente**, dado que la clave está disponible públicamente en el historial de commits del repositorio.

---

## 2. HALLAZGOS POR SEVERIDAD

### 🔴 CRÍTICO

| ID | Hallazgo | Evidencia | Impacto |
|----|----------|-----------|---------|
| **CRIT-001** | **API Key de Google Gemini hardcodeada en `.env`** | Archivo `.env` contiene `GEMINI_API_KEY="AIzaSyCIBBbvy_6OLaINDAF-J_gJ4BdXRsbldQw"` | Compromiso total de la clave; uso ilimitado por terceros, facturación abusiva y revocación de servicio por Google. |
| **CRIT-002** | **API Key expuesta en bundle de cliente via Vite** | `vite.config.ts` utiliza `define: { 'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY) }` | La clave se emite en JavaScript estático accesible desde el navegador; cualquier visitante puede recuperarla desde DevTools → Sources/Network. |
| **CRIT-003** | **Teléfono PII expuesto en código fuente** | `src/components/Contact.tsx` contiene `+57 310 240 3592` | Exposición de dato personal del fundador; riesgo de ingeniería social, spam telefónico y violación de regulaciones de privacidad. |
| **CRIT-004** | **Secret trackeado en Git pese a `.gitignore`** | `.env` está presente en el working tree a pesar de regla `.env*` en `.gitignore`. Commit `76a8a8e` eliminó `.env.example`. | El secret viaja en el historial de commits públicos; el archivo fue forzado al índice antes de la regla o des-trackeado de forma incompleta. |

### 🟠 ALTO

| ID | Hallazgo | Evidencia | Impacto |
|----|----------|-----------|---------|
| **HIGH-001** | **Endpoints de hackathon sin autenticación** | Endpoints `/chat`, `/register`, `/teams`, `/sponsors` consumidos desde `src/hackathon/ChatWidget.tsx` y `src/hackathon/Registro.tsx` sin headers de auth. | Exfiltración masiva de datos de participantes (PII), manipulación de registros y equipos, y abuso de recursos del backend (`hive-hackathon-api.vercel.app`). |
| **HIGH-002** | **Ausencia de tokens CSRF** | No se identifican tokens ni validación de origen en peticiones POST/GET a la API hackathon. | Posibilidad de ataques CSRF para modificar registros o enviar mensajes en nombre de usuarios legítimos. |

### 🟡 MEDIO

| ID | Hallazgo | Evidencia | Impacto |
|----|----------|-----------|---------|
| **MED-001** | **ContactPage simula envío sin endpoint real** | `Contact.tsx` utiliza `setTimeout` para simular envío; no hay backend real de contacto. | Degradación de la experiencia de usuario; si en el futuro se conecta un endpoint, el riesgo dependerá de su implementación. |
| **MED-002** | **Posible XSS en ChatWidget** | Renderizado directo de `m.content` sin sanitización en `src/hackathon/ChatWidget.tsx`. | Ejecución de scripts arbitrarios en el contexto del navegador del usuario, apropiación de sesiones o defacement. |
| **MED-003** | **Builds no reproducibles** | No existe `package-lock.json` versionado en el repositorio. | Instalación de dependencias no determinista; riesgo de supply-chain compromise si se comprometen paquetes npm o caché local. |

### 🔵 INFORMATIVO

| ID | Hallazgo | Evidencia | Impacto |
|----|----------|-----------|---------|
| **INFO-001** | **Directorio `public/binaries/` no auditable** | Directorio listado en `.gitignore`; contenido no escaneable por restricciones de sandbox. | Posible distribución de binarios no verificados; recomendación de auditar manualmente fuera del entorno de análisis. |
| **INFO-002** | **Falta de página 404 dedicada** | No se identificó manejo explícito de rutas no definidas. | Mínimo impacto funcional; recomendación de UX y SEO. |

---

## 3. RIESGOS DE NEGOCIO

1. **Costos Financieros Inmediatos (Crítico):** La API Key de Gemini expuesta permite a terceros consumir la cuota asignada. Un actor malicioso o un scraper automatizado puede generar facturación inesperada o agotar límites de uso, causando denegación de servicio legítimo.
2. **Daño Reputacional y Regulatorio (Crítico/Alto):** La exposición del teléfono de un fundador y la potencial filtración de datos de participantes de la hackathon violan principios de privacidad. En jurisdicciones como Colombia o bajo GDPR (si aplica a visitantes europeos), esto puede generar sanciones o demandas.
3. **Pérdida de Integridad de la Plataforma (Alto):** Endpoints sin autenticación permiten que cualquier actor modifique registros de equipos, patrocinadores o mensajes de chat, desacreditando el evento hackathon.
4. **Compromiso del Cliente (Medio):** Un vector XSS en el chat puede ser utilizado para distribuir malware, redirigir a usuarios a sitios de phishing o robar tokens de sesión si en el futuro se implementa autenticación.
5. **Riesgo de Cadena de Suministro (Medio):** La ausencia de `package-lock.json` impide la verificación criptográfica de dependencias, facilitando la introducción de paquetes comprometidos en pipelines de CI/CD.

---

## 4. ACCIONES INMEDIATAS (HOTFIX)

> **Prioridad 0 – Ejecutar en las próximas 2 horas:**

| Prioridad | Acción | Comando / Instrucción Concreta | Responsable |
|-----------|--------|-------------------------------|-------------|
| **P0** | Rotar la API Key de Google Gemini | 1. Acceder a [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials. 2. Revocar la clave `AIzaSyCIBBbvy_6OLaINDAF-J_gJ4BdXRsbldQw`. 3. Generar nueva clave. | Owner del proyecto GCP |
| **P0** | Eliminar la key del código fuente | Editar `.env` y eliminar la línea `GEMINI_API_KEY`. Editar `vite.config.ts` y eliminar la entrada `define` que expone la variable al cliente. | Desarrollador Lead |
| **P0** | Purgar el historial Git del secret | Utilizar `git filter-repo` o BFG Repo-Cleaner para eliminar la clave de todo el historial del repositorio. Luego forzar push a `main`. | DevOps / Git Admin |
| **P0** | Des-trackear `.env` del índice | Ejecutar: `git rm --cached .env && echo ".env" >> .gitignore && git commit -m "security: remove tracked .env and enforce ignore"` | Desarrollador |
| **P0** | Recrear `.env.example` seguro | Crear archivo `.env.example` con placeholders vacíos (ej. `GEMINI_API_KEY=YOUR_API_KEY_HERE`). | Desarrollador |
| **P1** | Mover teléfono PII a CMS/config externa | Eliminar el número `+57 310 240 3592` del código fuente; recuperarlo vía API o variable de entorno de build no pública. | Desarrollador |
| **P1** | Implementar proxy backend para Gemini | Nunca inyectar secrets en bundle cliente. Crear endpoint `/api/gemini` en un backend propio que almacene la key de forma segura (secrets manager / env vars de servidor) y reenvíe peticiones. | Backend Lead |
| **P1** | Asegurar endpoints hackathon | Implementar autenticación JWT + CSRF tokens + rate limiting en `hive-hackathon-api.vercel.app`. | Backend Lead |
| **P1** | Sanitizar output del chat | Instalar `dompurify` (`npm install dompurify`) y sanitizar `m.content` antes de renderizarlo en `ChatWidget.tsx`. | Frontend Lead |
| **P2** | Generar `package-lock.json` | Ejecutar `npm install` con versión fija de Node, versionar `package-lock.json` y auditar dependencias con `npm audit`. | Desarrollador |
| **P2** | Auditar `public/binaries/` | Revisar manualmente el contenido del directorio fuera de sandbox; eliminar archivos no necesarios o firmarlos criptográficamente. | DevOps / Seguridad |

---

## 5. EVIDENCIA FORENSE Y CADENA DE CUSTODIA

Para garantizar la trazabilidad y admisibilidad de la evidencia recolectada, se documenta la siguiente cadena de custodia:

- **Repositorio de origen:** `https://github.com/johpaz/hiveAgents.git`
- **Rama analizada:** `refs/heads/main`
- **Commit inicial identificado:** `b2cc6188...`
- **Autor del commit inicial:** `johpaz <johpaz252@gmail.com>`
- **Commit relevante (eliminación de `.env.example`):** `76a8a8e`
- **Método de adquisición:** Clonado desde origen remoto público; análisis realizado sobre working tree local.
- **Integridad:** El análisis se basó en revisión manual del código fuente y metadatos de Git. No se alteró la evidencia original durante la extracción.
- **Limitaciones de adquisición:**
  - Escaneo SAST con Semgrep y escaneo de filesystem con Trivy fueron **bloqueados** por ausencia del flag `--unsafe`.
  - Análisis de permisos de archivos y cálculo de hash SHA-256 recursivo global fueron **bloqueados** por restricciones de sandbox del entorno de análisis.
  - El directorio `public/binaries/` está ignorado por `.gitignore` y no pudo ser auditado dentro del entorno seguro.
  - **No se ejecutaron pruebas de validación activa** de la API Key contra los servidores de Google (pentest activo no autorizado).

---

## 6. RECOMENDACIONES ESTRATÉGICAS A LARGO PLAZO

1. **Implementar Secret Management:** Migrar de archivos `.env` locales a un gestor de secretos (HashiCorp Vault, AWS Secrets Manager, Google Secret Manager o Doppler) y consumirlos exclusivamente desde backend.
2. **Pre-Commit Hooks:** Instalar `husky` + `lint-staged` + `detect-secrets` (o `gitleaks`) para evitar que credenciales ingresen al repositorio en futuros commits.
3. **Pipeline de Seguridad en CI/CD:** Integrar Semgrep, Trivy y `npm audit` en el pipeline de Vercel/GitHub Actions, bloqueando el despliegue si se detectan secrets o dependencias vulnerables.
4. **Modelo de Amenazas (Threat Modeling):** Realizar sesiones de STRIDE o PASTA sobre el flujo de datos de la hackathon, especialmente para los endpoints de registro y chat.
5. **Política de PII:** Establecer un inventario de datos personales, aplicar enmascaramiento/masking en logs y limitar la retención de datos de participantes.
6. **Content Security Policy (CSP):** Desplegar headers CSP estrictos en Vercel para mitigar XSS incluso ante futuras introducciones de código inseguro.
7. **Hardening de la API Hackathon:** Aplicar principio de mínimo privilegio, validación de esquemas (Zod/Joi), rate limiting por IP y autenticación basada en tokens de corta duración.
8. **Reproducibilidad de Builds:** Fijar versiones de Node, usar `package-lock.json` (o `npm ci`) y considerar migración a `pnpm`/`yarn` con lockfiles versionados.

---

## 7. CONCLUSIÓN

El estado actual de seguridad del proyecto hiveApp presenta **vulnerabilidades críticas que requieren remediación inmediata**. La exposición de la API Key de Google Gemini en el frontend representa un riesgo financiero directo y tangible. La combinación de secrets en el historial Git, PII expuesta, endpoints abiertos y deficiencias de gobernanza de software indica que el proyecto carece actualmente de una postura de seguridad madura.

La ejecución de las **Acciones Inmediatas P0** (rotación de clave, purga Git, des-trackeo de `.env` y eliminación de secrets del bundle) debe considerarse **bloqueante para cualquier nuevo despliegue público**. Las recomendaciones estratégicas a largo plazo permitirán construir una base sólida que prevenga la recurrencia de estos hallazgos.

**Próxima revisión recomendada:** 30 días después de la remediación, incluyendo escaneo SAST completo y revisión manual de la API hackathon.

---

*Fin del Informe Ejecutivo.*
