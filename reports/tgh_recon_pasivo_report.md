# Informe Ejecutivo — Reconocimiento Pasivo Inicial
**Objetivo:** `https://thinkglobalhealth.org/`
**Programa:** Bugcrowd — `cfr`
**Fase:** Reconocimiento pasivo / no intrusivo (fase 1)
**Alcance de la sesión:** Solo apex. `static.thinkglobalhealth.org` es *in-scope* pero **NO** se siguió en esta sesión.
**Riesgo operativo de la sesión:** Bajo (recon pasivo; sin fuzzing, sin POST, sin autenticación).

---

## 1. Resumen ejecutivo

Se ejecutó un reconocimiento pasivo y no intrusivo sobre el apex `https://thinkglobalhealth.org/` dentro del programa Bugcrowd `cfr`. Se realizaron **tres peticiones GET** (raíz, `/robots.txt` y `/sitemap.xml`), sin crawling profundo, sin fuzzing, sin POST y sin logins.

Hallazgos principales de esta fase:

- **Stack confirmado con alta confianza:** plataforma **Next.js (App Router) + Turbopack** (build id `0e9a9c5`), con assets estáticos servidos desde el subdominio `static.thinkglobalhealth.org`. Se detectó **reCAPTCHA v3 (Google)** y **Datawrapper**; **Typekit** con confianza media.
- **No confirmado (sin evidencia):** Cloudflare CDN y nginx. **Probablemente refutable:** PHP y New Relic (no evidenciados; el stack visible es Node/Next.js).
- **Security headers:** quedan en estado **PENDING-VERIFICACION**. El toolset de esta sesión (`web_fetch`) no expone response headers, por lo que **no se afirma ni presencia ni ausencia** de cabeceras.
- **Superficie mínima mapeada:** una única entrada de usuario visible (`/search?full_text=`, SearchAction) y un formulario de newsletter protegido por reCAPTCHA v3 (no se envió POST).
- **Sin sitemap declarado:** `/sitemap.xml` responde 404 (página HTML de Next.js) y no se declara sitemap en `robots.txt`.

**Conclusión:** la fase 1 delimita un stack moderno (Next.js) y una superficie de entrada reducida en capa visible. No se generó ninguna vulnerabilidad ni acción intrusiva. Las hipótesis H1–H3 requieren verificación con tooling adicional (curl/openssl) en la siguiente fase.

> **Nota de rigor:** ningún hallazgo de seguridad se declara como "confirmado" en este informe. Todo elemento no verificado se marca explícitamente como *hipótesis* o *PENDING-VERIFICACION*. No se inventan hallazgos; todo deriva de los datos persistidos en `findings/tgh_recon_pasivo.json`.

---

## 2. Alcance y método

**Alcance de la sesión (restringido):**
- Solo **apex** `thinkglobalhealth.org`.
- `static.thinkglobalhealth.org` está *in-scope* en el programa, pero **no se siguió** en esta sesión pasiva (se reserva para fase posterior).

**Método:**
- Reconocimiento **pasivo / no intrusivo**: solo lectura de recursos públicos mediante GET.
- **Restricciones explícitas:**
  - Solo verbos **GET** (sin POST, PUT, DELETE, etc.).
  - **Sin fuzzing** de parámetros o rutas.
  - **Sin** intentos de autenticación, login o enumeración de cuentas.
  - **Toolset limitado:** `web_fetch` (expone únicamente el **cuerpo** de la respuesta; **no** expone response headers ni response time).
  - **Desactivados en el entorno:** `whois`, `dig`, `nmap` (política) → DNS/WHOIS/escaneo de puertos **no ejecutados**.
- **Consecuencia directa:** los objetivos "present/missing" de security headers quedaron en **PENDING-VERIFICACION** y no se declaran como ausentes.

---

## 3. Stack tecnológico — confirmado vs no confirmado

| Tecnología | Confianza | Estado | Evidencia / nota |
|---|---|---|---|
| **Next.js (App Router) + Turbopack** | **Alta** | **Confirmado** | Chunks `turbopack-*.js`, rutas `/_next/static/chunks/`, payloads `self.__next_f`, `meta next-size-adjust`, RSC fragment markers. Build id `0e9a9c5`. |
| **CDN/estáticos en `static.thinkglobalhealth.org`** | **Alta** | **Confirmado** | Todos los assets JS/CSS servidos desde `https://static.thinkglobalhealth.org/0e9a9c5/_next/...`. Subdominio *in-scope*, **no seguido** en esta sesión. |
| **reCAPTCHA v3 (Google) + Datawrapper** | **Alta** | **Confirmado** | `window.tgh_settings.recaptchaSiteId 6Ldap7UrAAAA...`, `google.com/recaptcha/api.js`, `datawrapper.dwcdn.net`. |
| **Typekit (Adobe Fonts)** | **Media** | Parcialmente confirmado | `use.typekit.net/ygq0fud.css` y clases de fuente con hash. |
| **Cloudflare CDN** | **Baja** | **NO confirmado** | Sin headers accesibles. Requiere `curl -sI` (`server`/`cf-ray`). |
| **nginx** | **Baja** | **NO confirmado** | Sin `Server` header disponible. |
| **PHP** | **Baja** | **Probablemente refutable** | NO evidenciada; el stack visible es Node/Next.js. |
| **New Relic** | **Baja** | **NO observada** | No observada en HTML ni assets. |

**Security headers:** **PENDING-VERIFICACION** (vacíos de propósito — ni presentes ni ausentes). Requiere `curl -sSI` sobre apex y `static.*` para evaluar CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

---

## 4. Superficie de ataque mapeada

**Paths observados:**
- `/search/`, `/site-search/`, `/_next/static/`
- `/lemonde-journal-patch.css`
- `/favicon.png`, `/favicon-32x32.png`, `/favicon-96x96.png`, `/apple-touch-icon.png`

**Endpoints:**
- `/search?full_text={search_term_string}` (urlTemplate de SearchAction) — **única entrada de usuario visible en la primera capa**.

**Formularios:**
- Newsletter / Subscribe — protegido con **reCAPTCHA v3** (no se envió POST).

**Parámetros de consulta:**
- `full_text` (única entrada de usuario visible).

**API endpoints visibles:** ninguno.
**Paths de administración visibles:** ninguno.

> Observación: la superficie en capa visible es reducida y orientada a un sitio editorial/Next.js. No se observan paneles de administración, APIs REST/GraphQL ni parámetros de estado en la primera capa.

---

## 5. Hipótesis para la siguiente fase

- **H1 — Sitemap ausente:** el sitemap no existe en `/sitemap.xml` (404) ni está declarado en `robots.txt`; las rutas solo serían descubribles por inferencia. *(riesgo: bajo)*
- **H2 — Headers / edge vs origin:** las security headers pueden estar presentes o mal configuradas, con posible **inconsistencia entre el apex y `static.thinkglobalhealth.org`**. *(riesgo: bajo)*
- **H3 — Comportamiento de `/search?full_text=`:** el parámetro puede reflejar/procesar la entrada de forma insegura. **Solo hipótesis**; explorar en una sesión posterior **controlada y con GET benigno**, respetando límites de rate. *(riesgo: bajo)*

---

## 6. Brechas de evidencia y próximos pasos

**Brechas de evidencia detectadas en esta fase:**
1. **Response headers no capturados** (`web_fetch` solo expone el cuerpo) → security headers en PENDING-VERIFICACION.
2. **TLS y cookies no verificables** con el toolset actual.
3. **DNS/WHOIS no ejecutados** (`whois`/`dig` deshabilitados por política).
4. **Redirección apex→www no verificada** (JSON-LD usa `www.` en `@id`/canonical).
5. **Inconsistencia SSR por ruta:** `recaptchaSiteId` `6Ldap7UrAAAA...` en raíz vs `undefined` en robots/sitemap.

**Próximos pasos (fase 2):**
- `curl -sSI https://thinkglobalhealth.org/` → capturar headers (CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Server`, `cf-ray`).
- `curl -sSI https://static.thinkglobalhealth.org/...` → comparar headers entre apex y subdominio (H2).
- Verificación **TLS** (versión, cert, caducidad) con `curl`/`openssl`.
- **DNS/WHOIS** cuando el entorno lo permita (`dig`, `whois`) para resolver la posible redirección apex→www.
- Exploración **controlada (solo GET benigno, rate-limited)** de `/search?full_text=` (H3).
- Confirmar/refutar presencia de Cloudflare y nginx vía `Server`/`cf-ray`.

---

## 7. Anexo — Requests realizados y evidencia

| # | Método | URL | Código HTTP | Estado | Nota de evidencia |
|---|---|---|---|---|---|
| 1 | GET | `https://thinkglobalhealth.org/` | 200 | ok | Headers **no capturados** (web_fetch solo expone cuerpo; requiere `curl -sI`). |
| 2 | GET | `https://thinkglobalhealth.org/robots.txt` | 200 | ok | `Disallow: /search/ /site-search/ /_next/static/`. **Sin declaración de sitemap**. |
| 3 | GET | `https://thinkglobalhealth.org/sitemap.xml` | 404 | not_found | Devuelve **página HTML de Next.js** (no XML). |

**Notas complementarias (evidencia de la sesión):**
- **JSON-LD:** usa `www.thinkglobalhealth.org` como `@id`/canonical → posible redirección apex→www (**no verificada**).
- **Inconsistencia SSR por ruta:** `recaptchaSiteId` `6Ldap7UrAAAA...` en la raíz vs `undefined` en robots/sitemap (template SSR por ruta).
- **TLS/cookies:** no verificables con el toolset actual (requiere `curl`/`openssl`).
- **Herramientas deshabilitadas:** `whois`/`dig`/`nmap` → DNS/WHOIS no ejecutados.

**Fuente de datos:** `findings/tgh_recon_pasivo.json`.
**Riesgo global de la sesión:** **bajo** (reconocimiento pasivo).

---

*Fin del informe. Estado: completado con evidencia verificable de las 3 peticiones GET. Elementos no verificados marcados explícitamente como PENDING-VERIFICACION o hipótesis.*
