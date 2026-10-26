# Verificador PoC — Vulnerabilidades de Node.js

Herramienta de verificación defensiva para identificar posibles condiciones de exposición a vulnerabilidades de seguridad de Node.js mediante pruebas funcionales acotadas e inspección estática del código fuente.

El objetivo es facilitar una primera evaluación técnica de aplicaciones Node.js sin utilizar la versión instalada como único criterio de detección.

> **Aviso:** este proyecto es una herramienta preliminar de verificación. Los resultados no constituyen una confirmación definitiva ni descartan la presencia de las vulnerabilidades analizadas.

## Características

- Verificaciones funcionales preliminares de DNS y validación TLS.
- Análisis estático de referencias a API potencialmente relevantes.
- Búsqueda de archivos de código JavaScript, TypeScript y manifiestos JSON.
- Ejecución desde Bash, sin instalar dependencias adicionales de Node.js.
- Generación de un informe de texto con fecha de ejecución.
- Sin comparación de versiones como criterio principal.
- Sin escaneo de direcciones IP ni de destinos externos configurados.
- Sin explotación intencional de las vulnerabilidades.

## Vulnerabilidades contempladas

| CVE | Severidad informada | Componente o comportamiento |
|---|---|---|
| CVE-2026-111497 | Alta | Escritura fuera de límites en el decodificador Brotli |
| CVE-2026-105482 | Alta | Truncamiento de nombres con carácter NUL en resolución DNS |
| CVE-2026-105483 | Alta | Validación del nombre de host en certificados TLS |
| CVE-2026-106069 | Alta | Validación de certificados TLS y normalización de nombres |
| CVE-2026-105481 | Media | Procesamiento de respuestas HTTP recibidas antes de la solicitud |
| CVE-2026-106072 | Media | Validación de certificados para representaciones IPv4 no canónicas |
| CVE-2026-106074 | Media | Reutilización de valores aleatorios en aplicaciones ejecutables y snapshots |
| CVE-2026-106070 | Baja | Validación de archivos ZIP mediante `zlib.ZipFile` |
| CVE-2026-106071 | Baja | Reglas comodín del modelo de permisos |
| CVE-2026-106073 | Baja | Controles de permisos relacionados con `fs.realpathSync()` |

Las severidades se incluyen como referencia del listado inicial y deben contrastarse con los avisos oficiales correspondientes.

## Requisitos

- Linux o un entorno Unix compatible.
- Bash.
- Node.js disponible en `PATH` para las comprobaciones funcionales.
- GNU `grep` para el análisis estático, si se desea utilizar esa función.

No requiere privilegios de administrador ni la instalación de paquetes adicionales.

## Instalación

Clonar el repositorio:

```bash
git clone https://github.com/USUARIO/verificador-poc.git
cd verificador-poc
```

Dar permisos de ejecución:

```bash
chmod +x verificador_poc.sh
```

Reemplazar `USUARIO/verificador-poc` por la dirección real del repositorio.

## Uso

### Analizar el directorio actual

```bash
./verificador_poc.sh
```

### Analizar una aplicación específica

```bash
./verificador_poc.sh /ruta/al/proyecto
```

### Analizar un proyecto web

Por ejemplo:

```bash
./verificador_poc.sh /var/www/aplicacion
```

El script genera un informe con un nombre similar a:

```text
verificador_poc_YYYYMMDD_HHMMSS.txt
```

El informe se guarda en el directorio de trabajo desde el que se ejecuta el script.

## Interpretación de resultados

| Resultado | Significado |
|---|---|
| `DETECTADO` | Se observó el comportamiento definido por una prueba. Requiere validación adicional antes de confirmar la CVE. |
| `NO DETECTADO` | La prueba no reprodujo el comportamiento esperado. No garantiza que el sistema sea seguro. |
| `REVISAR` | Se identificó una condición que necesita investigación adicional. |
| `NO EVALUADO` | La comprobación no pudo realizarse o no existe una prueba implementada. |
| `INFO` | Información de inventario o contexto técnico. |

La presencia de una API como `createBrotliDecompress`, `dns.resolve`, `crypto.randomUUID` o `fs.realpathSync` no implica por sí sola que una aplicación sea vulnerable.

## Alcance y limitaciones

El proyecto es una herramienta de triaje inicial, no un escáner exhaustivo de vulnerabilidades.

Las comprobaciones funcionales incluidas son preliminares. Para confirmar cada CVE se necesitan casos de prueba específicos, reproducibles y vinculados con el comportamiento vulnerable descrito por el proveedor.

En particular:

- **Brotli:** requiere pruebas controladas de decodificación y manejo de errores.
- **DNS:** requiere comprobar cómo se rechazan los nombres que contienen bytes NUL.
- **TLS:** requiere casos de prueba de normalización y validación de nombres y direcciones.
- **HTTP:** requiere un entorno aislado que permita verificar el orden de solicitudes y respuestas.
- **Crypto y snapshots:** requiere examinar el comportamiento de aplicaciones SEA y snapshots.
- **ZIP:** requiere pruebas de validación de archivos ZIP malformados.
- **Modelo de permisos:** requiere ejecutar pruebas controladas con permisos restringidos y reglas comodín.
- **Sistema de archivos:** requiere
