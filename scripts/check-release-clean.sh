#!/usr/bin/env bash
# В релизном бинарнике не должно быть следов инструментов разработки (ADR 0011).
set -euo pipefail

bin="${1:-target/release/protoledger}"
[ -f "$bin" ] || { echo "нет $bin — сначала cargo build --release -p protoledger"; exit 1; }

found=0
for pattern in swagger 'api/docs' PROTOLEDGER_DEV_TOKEN 'localhost:3000' 'X-Protoledger-Token.*requestInterceptor'; do
  if grep -aqiE -- "$pattern" "$bin"; then
    echo "в $bin найдено: $pattern"
    found=1
  fi
done
[ "$found" -eq 0 ] && echo "релизный бинарник чист от dev-следов"
exit "$found"
