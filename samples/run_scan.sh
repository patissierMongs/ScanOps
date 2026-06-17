#!/bin/bash
# WSL에서 실제 nmap 으로 localhost 스캔 → XML 산출. 인자: 출력파일 [stop_port]
set -e
OUT="$1"
STOP="${2:-}"
cd /tmp
python3 -m http.server 8080 >/dev/null 2>&1 & P1=$!
python3 -m http.server 9000 >/dev/null 2>&1 & P2=$!
P3=""
if [ "$STOP" != "3000" ]; then
  python3 -m http.server 3000 >/dev/null 2>&1 & P3=$!
fi
sleep 1.5
nmap -sV -p 22,80,443,3000,3306,8080,9000 127.0.0.1 -oX "$OUT"
kill $P1 $P2 $P3 2>/dev/null || true
echo "--- open ports ---"
grep -o 'portid="[0-9]*"><state state="open"' "$OUT" | grep -o '[0-9]*' | sort -un | tr '\n' ' '
echo ""
