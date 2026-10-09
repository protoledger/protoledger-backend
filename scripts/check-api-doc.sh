#!/usr/bin/env bash
# Каждый путь из openapi.yaml должен быть описан в API.md.
set -euo pipefail

spec="${1:-openapi.yaml}"
doc="${2:-API.md}"

if [ ! -f "$spec" ]; then
  echo "нет $spec — контракт ещё не заведён, пропускаю"
  exit 0
fi
[ -f "$doc" ] || { echo "есть $spec, но нет $doc"; exit 1; }

paths="$(awk '/^paths:/{p=1; next} p && /^[^[:space:]]/{p=0} p && /^  \/[^:]*:[[:space:]]*$/{sub(/^  /,""); sub(/:[[:space:]]*$/,""); print}' "$spec")"
missing=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  grep -qF -- "$p" "$doc" || { echo "в $doc не описан: $p"; missing=1; }
done <<< "$paths"

[ "$missing" -eq 0 ] && echo "API.md покрывает все пути ($(printf '%s\n' "$paths" | grep -c .))"
exit "$missing"
