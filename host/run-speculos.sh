#!/bin/bash
# รัน Speculos ใน container แยก และเปิดพอร์ตให้เฉพาะ 127.0.0.1
#
# Speculos bind 0.0.0.0 ตายตัวในโค้ด (ตั้งค่าไม่ได้) จึงห้ามรันด้วย --network host
# หรือรันตรง ๆ บนเครื่องที่เข้าถึงจากภายนอกได้ ให้รันใน network แบบ bridge
# แล้ว publish พอร์ตไปที่ 127.0.0.1 อย่างเดียวแบบนี้แทน
#
# ใช้: host/run-speculos.sh            (Ctrl+C เพื่อปิด)
#     MODEL=stax ELF=build/stax/bin/app.elf host/run-speculos.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${SPECULOS_IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}
MODEL=${MODEL:-nanosp}
ELF=${ELF:-build/nanos2/bin/app.elf}
API_PORT=${API_PORT:-5000}
APDU_PORT=${APDU_PORT:-9999}

if [ ! -f "$ROOT/$ELF" ]; then
    echo "ไม่พบ $ELF: build แอปก่อน (make BOLOS_SDK=\$NANOSP_SDK)" >&2
    exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -qx ledger-ssh-speculos; then
    echo "Speculos (ledger-ssh-speculos) ยังรันอยู่: ปิดก่อนด้วย docker stop ledger-ssh-speculos" >&2
    exit 1
fi

exec docker run --rm --init --name ledger-ssh-speculos \
    -p "127.0.0.1:${API_PORT}:5000" \
    -p "127.0.0.1:${APDU_PORT}:9999" \
    -v "$ROOT:/app:ro" -w /app \
    "$IMAGE" \
    speculos "$ELF" --model "$MODEL" --display headless --api-port 5000 --apdu-port 9999
