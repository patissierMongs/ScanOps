#!/bin/bash
# nmap --resume 실증 (제대로): 응답하는 loopback 호스트 다수를 전포트 스캔 →
# 중간에 완료된 호스트가 생기도록 한 뒤 끊고 --resume 으로 이어가기.
cd /tmp
rm -f r.nmap r.xml r.gnmap
echo "=== 1) -oA(.nmap/.xml/.gnmap 동시) 로 스캔 시작, 5초 뒤 Ctrl-C ==="
# 호스트 1개씩(--max-hostgroup 1) + 포트당 지연 → 호스트가 순차 완료되어
# 중단 시점에 '완료 N개 + 미완료 다수'가 생긴다. 127.0.0.1~40 전부 loopback=응답.
nmap -Pn -p 1-120 --scan-delay 25ms --max-hostgroup 1 127.0.0.1-40 -oA r >/dev/null 2>&1 &
PID=$!
sleep 7
kill -INT $PID 2>/dev/null
wait $PID 2>/dev/null
echo "생성된 파일:"; ls -1 r.* 2>/dev/null
DONE1=$(grep -c "Nmap scan report" r.nmap)
echo "중단 시점 완료 호스트: $DONE1"

echo ""
echo "=== 2) nmap --resume r.nmap (옵션 없이 로그만) ==="
nmap --resume r.nmap >/dev/null 2>&1
DONE2=$(grep -c "Nmap scan report" r.nmap)
echo "재개 후 완료 호스트: $DONE2"
grep "Nmap done" r.nmap | tail -1
echo ""
if [ "$DONE2" -gt "$DONE1" ]; then
  echo ">>> RESUME 동작 확인: $DONE1 → $DONE2 (이어서 추가 스캔됨)"
else
  echo ">>> RESUME 추가 없음 (이미 완료였거나 중단이 너무 늦음)"
fi
echo ""
echo "=== 3) XML 도 함께 갱신되나? (ScanOps 파싱용) ==="
ls -l r.xml | awk '{print "r.xml size:", $5}'
grep -c "<host" r.xml
