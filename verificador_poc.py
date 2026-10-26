#!/usr/bin/env python3
"""
verificador_poc.py
Verificador preliminar defensivo de CVE de Node.js.

Realiza inventario y análisis estático. No explota vulnerabilidades,
no escanea direcciones IP ni conecta con servidores externos.
No utiliza la versión de Node.js como criterio de vulnerabilidad.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

CVE = [
    ("CVE-2026-111497", "Alta", "Decodificador Brotli"),
    ("CVE-2026-105482", "Alta", "Resolución DNS y carácter NUL"),
    ("CVE-2026-105483", "Alta", "Validación de nombres TLS"),
    ("CVE-2026-106069", "Alta", "Normalización de nombres TLS"),
    ("CVE-2026-105481", "Media", "Respuestas HTTP anticipadas"),
    ("CVE-2026-106072", "Media", "Validación TLS de IPv4 no canónicas"),
    ("CVE-2026-106074", "Media", "Crypto, snapshots y aplicaciones SEA"),
    ("CVE-2026-106070", "Baja", "Validación de archivos ZIP"),
    ("CVE-2026-106071", "Baja", "Modelo de permisos y reglas comodín"),
    ("CVE-2026-106073", "Baja", "fs.realpathSync y permisos"),
]

SKIP_DIRS = {
    ".git", "node_modules", ".next", "dist", "build",
    ".venv", "venv", "__pycache__", ".pytest_cache"
}

EXTENSIONS = {
    ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml"
}

PATTERNS = {
    "Brotli": r"\b(createBrotliDecompress|brotliDecompress)\b",
    "DNS": r"\b(dns\.resolve|dns\.lookup|resolve4|resolve6)\b",
    "TLS": r"\b(checkServerIdentity|rejectUnauthorized|servername)\b",
    "HTTP": r"\b(http\.request|https\.request|http\.Agent|https\.Agent)\b",
    "Crypto": r"\b(randomUUID|randomInt)\s*\(",
    "ZIP": r"\b(ZipFile|createUnzip|unzip)\b",
    "Permisos": r"--permission|--allow-fs-(read|write)",
    "Filesystem": r"\brealpathSync\b",
    "SEA/snapshots": r"\b(snapshot|sea\.config|single executable application)\b",
}

EXCLUDED_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "pnpm-lock.yaml", "yarn.lock"
}

MAX_FILES = 10000
MAX_FILE_SIZE = 2 * 1024 * 1024


def project_files(root):
    total = 0

    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for name in files:
            path = Path(current) / name

            if path.suffix.lower() not in EXTENSIONS:
                continue

            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            yield path
            total += 1

            if total >= MAX_FILES:
                return


def analyze_project(root):
    counts = {name: 0 for name in PATTERNS}
    manifests = []
    files_analyzed = 0

    compiled = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in PATTERNS.items()
    }

    for path in project_files(root):
        files_analyzed += 1

        if path.name in EXCLUDED_NAMES:
            manifests.append(str(path.relative_to(root)))

        try:
            content = path.read_text(
                encoding="utf-8", errors="replace"
            )
        except (OSError, UnicodeError):
            continue

        for name, pattern in compiled.items():
            if pattern.search(content):
                counts[name] += 1

    return counts, sorted(set(manifests)), files_analyzed


def inspect_node():
    executable = shutil.which("node")

    if not executable:
        return {
            "available": False,
            "message": "Node.js no encontrado en PATH"
        }

    code = r"""
const z = require('node:zlib');
const c = require('node:crypto');
const f = require('node:fs');
const d = require('node:dns');
const h = require('node:http');
const t = require('node:tls');

console.log(JSON.stringify({
  brotli: typeof z.createBrotliDecompress === 'function',
  dnsResolve: typeof d.resolve === 'function',
  tlsIdentity: typeof t.checkServerIdentity === 'function',
  httpAgent: typeof h.Agent === 'function',
  randomUUID: typeof c.randomUUID === 'function',
  randomInt: typeof c.randomInt === 'function',
  realpathSync: typeof f.realpathSync === 'function'
}));
"""

    try:
        result = subprocess.run(
            [executable, "-e", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            return {
                "available": True,
                "path": executable,
                "message": "No se pudo inspeccionar el runtime"
            }

        return {
            "available": True,
            "path": executable,
            "apis": json.loads(result.stdout.strip())
        }

    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {
            "available": True,
            "path": executable,
            "message": "Error durante la inspección"
        }


def main():
    parser = argparse.ArgumentParser(
        description="Verificador PoC preliminar de CVE de Node.js"
    )

    parser.add_argument(
        "directorio",
        nargs="?",
        default=".",
        help="Directorio del proyecto (por defecto: actual)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Ruta del informe de salida"
    )

    args = parser.parse_args()
    root = Path(args.directorio).expanduser().resolve()

    if not root.is_dir():
        parser.error(f"El directorio no existe: {root}")

    timestamp = datetime.datetime.now().astimezone().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = Path(args.output).expanduser() if args.output else Path(
        f"verificador_poc_{timestamp}.txt"
    )

    lines = []

    def log(message=""):
        print(message)
        lines.append(message)

    log("=" * 65)
    log(" VERIFICADOR PoC DEFENSIVO - NODE.JS")
    log("=" * 65)
    log(f"Fecha: {datetime.datetime.now().astimezone().isoformat()}")
    log(f"Directorio: {root}")
    log("Criterio: análisis estático e inventario; no versión.")
    log("Conexiones externas: ninguna.")
    log()

    log("--- Inspección del runtime ---")
    runtime = inspect_node()

    if runtime["available"]:
        log(f"[INFO] Ejecutable: {runtime['path']}")

        if "apis" in runtime:
            for api, available in runtime["apis"].items():
                log(f"[INFO] API {api}: {'disponible' if available else 'no disponible'}")
        else:
            log(f"[NO EVALUADO] {runtime['message']}")
    else:
        log(f"[NO EVALUADO] {runtime['message']}")

    log()
    log("--- Inventario del proyecto ---")
    counts, manifests, files_analyzed = analyze_project(root)

    log(f"Archivos de código analizados: {files_analyzed}")

    if manifests:
        log("Manifiestos y archivos de dependencias:")
        for item in manifests:
            log(f"  {item}")
    else:
        log("No se encontraron manifiestos conocidos.")

    log()
    log("--- Referencias estáticas ---")

    for category, count in counts.items():
        log(f"{category}: {count} archivo(s) con coincidencias")

    log()
    log("--- Evaluación por CVE ---")

    evaluations = [
        ("CVE-2026-111497", "REVISAR",
         "Brotli requiere casos de regresión específicos."),
        ("CVE-2026-105482", "NO EVALUADO",
         "No se ejecutó una prueba funcional de DNS con NUL."),
        ("CVE-2026-105483", "NO EVALUADO",
         "No se ejecutó una prueba específica de validación TLS."),
        ("CVE-2026-106069", "NO EVALUADO",
         "Falta la prueba de normalización TLS afectada."),
        ("CVE-2026-105481", "NO EVALUADO",
         "Falta la prueba de respuestas HTTP anticipadas."),
        ("CVE-2026-106072", "NO EVALUADO",
         "Falta la prueba TLS de representaciones no canónicas."),
        ("CVE-2026-106074", "REVISAR",
         "Revisar el uso de crypto junto con snapshots y SEA."),
        ("CVE-2026-106070", "NO EVALUADO",
         "Falta la prueba de regresión para ZIP."),
        ("CVE-2026-106071", "REVISAR",
         "Revisar reglas comodín y configuración de permisos."),
        ("CVE-2026-106073", "REVISAR",
         "Revisar realpathSync bajo permisos restringidos."),
    ]

    severity = {item[0]: item[1] for item in CVE}

    for cve, status, detail in evaluations:
        log(f"[{status}] {cve} ({severity[cve]}): {detail}")

    log()
    log("--- Limitaciones ---")
    log("Este script NO confirma ni descarta definitivamente las CVE.")
    log("Las referencias de API son indicios, no pruebas de vulnerabilidad.")
    log("Las pruebas funcionales deben ejecutarse en un laboratorio aislado.")
    log("Se recomienda contrastar cada CVE con los avisos oficiales.")

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"ERROR al guardar el informe: {error}")
        return 1

    print(f"\nInforme guardado en: {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
