#!/usr/bin/env bash
# اجرای سریع NetScanner
#   ./run.sh            → رابط وب روی پورت 8000
#   ./run.sh scan       → اسکن خط فرمان شبکهٔ محلی
#   ./run.sh 192.168.1.0/24 report.html
#
# اگر با دسترسی root اجرا شود (sudo)، لایه‌های ARP/ICMP/TCP-SYN خام هم فعال می‌شوند
# و هیچ دستگاه زنده‌ای از قلم نمی‌افتد.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "پایتون پیدا نشد"; exit 1; }

if [ "${1:-serve}" = "scan" ]; then
  shift || true
  exec "$PY" -m netscan "$@"
fi

if [ -n "${1:-}" ] && [ "$1" != "serve" ]; then
  TARGET="$1"
  OUT="${2:-netscan-report.html}"
  exec "$PY" -m netscan --target "$TARGET" --html "$OUT" --json "${OUT%.html}.json"
fi

PORT="${PORT:-8000}"
echo "اجرای رابط وب روی http://localhost:${PORT}  (برای توقف: Ctrl+C)"
if [ "$(id -u)" != "0" ]; then
  echo "نکته: برای اسکن کامل‌تر با دسترسی مدیر اجرا کنید:  sudo ./run.sh"
fi
exec "$PY" -m netscan --serve --host 0.0.0.0 --port "$PORT"
