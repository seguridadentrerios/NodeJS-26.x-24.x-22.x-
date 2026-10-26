
#!/usr/bin/env bash
# verificador_poc.sh
# PoC defensivo de comprobación de CVE de Node.js.
# Sin comparación de versiones, IPs ni destinos externos.

set -u
export LC_ALL=C

ROOT="${1:-.}"
OUT="verificador_poc_$(date +%Y%m%d_%H%M%S).txt"

[[ -d "$ROOT" ]] || {
    echo "Uso: $0 [directorio_proyecto]"
    exit 1
}

ROOT="$(cd "$ROOT" && pwd -P)" || exit 1
exec > >(tee "$OUT") 2>&1

echo "=== Node.js CVE PoC defensivo ==="
echo "Fecha: $(date -Is)"
echo "Proyecto: $ROOT"
echo

if ! command -v node >/dev/null 2>&1; then
    echo "[NO EVALUADO] Node.js no está disponible."
    exit 2
fi

# Prueba funcional DNS: una entrada con NUL debe rechazarse.
echo "--- CVE-2026-105482: DNS NUL ---"
node - <<'NODE'
const dns = require('node:dns');

try {
  dns.resolve('example.com\0.invalid', (err) => {
    if (err) {
      console.log('[NO DETECTADO] La API rechazó la entrada.');
    } else {
      console.log('[DETECTADO] La API aceptó/resolvió la entrada con NUL.');
    }
  });
} catch (e) {
  console.log('[NO DETECTADO] Entrada rechazada:', e.code || e.name);
}
NODE

# Prueba TLS: usa un certificado ficticio y no conecta a ningún servidor.
echo
echo "--- CVE-2026-105483: normalización TLS ---"
node - <<'NODE'
const tls = require('node:tls');

const cert = {
  subject: { CN: '127.0.0.1' },
  subjectaltname: 'DNS:127.0.0.1'
};

try {
  const err = tls.checkServerIdentity('１２７.0.0.1', cert);
  if (err === undefined) {
    console.log('[DETECTADO] Se aceptó un nombre Unicode con SAN DNS.');
  } else {
    console.log('[NO DETECTADO] La identidad fue rechazada.');
  }
} catch (e) {
  console.log('[NO DETECTADO] Rechazo por excepción:', e.code || e.name);
}
NODE

# Inventario estático: informa archivos que usan las API relevantes.
echo
echo "--- Inventario estático ---"

if command -v grep >/dev/null 2>&1; then
  for api in \
    'createBrotliDecompress' \
    'dns.resolve' \
    'checkServerIdentity' \
    'http.Agent' \
    'randomUUID' \
    'randomInt' \
    'ZipFile' \
    'allow-fs-read' \
    'allow-fs-write' \
    'realpathSync'
  do
    count=$(
      grep -rIlE \
        --exclude-dir=.git \
        --exclude-dir=node_modules \
        --exclude-dir=dist \
        --exclude-dir=build \
        --include='*.js' --include='*.cjs' \
        --include='*.mjs' --include='*.ts' \
        --include='*.json' \
        -- "$api" "$ROOT" 2>/dev/null | wc -l
    )
    printf '%-28s %s archivo(s)\n' "$api" "$count"
  done
else
  echo "[NO EVALUADO] grep no disponible."
fi

echo
echo "--- CVE que requieren PoC específico ---"
echo "[REVISAR] CVE-2026-111497: Brotli; no se ejecuta entrada corrupta."
echo "[REVISAR] CVE-2026-106069: TLS con IPv4 no canónica."
echo "[REVISAR] CVE-2026-105481: respuestas HTTP anticipadas."
echo "[REVISAR] CVE-2026-106072: TLS con IPv4 no canónica."
echo "[REVISAR] CVE-2026-106074: snapshots/SEA y cachés criptográficas."
echo "[REVISAR] CVE-2026-106070: validación de cabeceras ZIP."
echo "[REVISAR] CVE-2026-106071: comodines del modelo de permisos."
echo "[REVISAR] CVE-2026-106073: realpathSync y permisos."

echo
echo "Informe guardado en: $OUT"
echo "NOTA: una prueba negativa no demuestra que el sistema esté libre de CVE."
