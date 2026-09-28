#!/bin/bash
# ทดสอบ ssh login ผ่าน ledger agent กับ sshd ชั่วคราวที่ 127.0.0.1 เท่านั้น
# - ไม่แตะ ~/.ssh/authorized_keys: key อยู่ในไดเรกทอรีชั่วคราว
# - ปิด sshd และลบไดเรกทอรีทิ้งเสมอ (trap EXIT) แม้ทดสอบล้มเหลว
# ต้องรัน agent.js อยู่ และ export SSH_AUTH_SOCK=/tmp/nano-ssh-agent.sock ไว้ก่อน
set -euo pipefail

PORT=${PORT:-22022}
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d)
chmod 700 "$D"

cleanup() {
    [ -f "$D/sshd.pid" ] && kill "$(cat "$D/sshd.pid")" 2>/dev/null || true
    rm -rf "$D"
    echo "ปิด sshd ชั่วคราวและลบ $D แล้ว"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$D/host_key"
cp "$HERE/speculos-test-key.pub" "$D/authorized_keys"
cat > "$D/sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $PORT
HostKey $D/host_key
PidFile $D/sshd.pid
AuthorizedKeysFile $D/authorized_keys
AllowUsers $(whoami)
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
EOF

/usr/sbin/sshd -f "$D/sshd_config" -E "$D/sshd.log"
sleep 0.5

# KNOWN_HOSTS_FILE: ให้ ssh เขียน host key ของ sshd ชั่วคราวลงไฟล์นี้ (เช่นให้ dashboard อ่าน)
# HASH_KNOWN_HOSTS=yes|no: บังคับรูปแบบบรรทัดใน known_hosts (ไม่ตั้ง = ตามค่าของระบบ)
EXTRA=()
[ -n "${HASH_KNOWN_HOSTS:-}" ] && EXTRA+=(-o "HashKnownHosts=$HASH_KNOWN_HOSTS")

echo "กำลัง login ... กดยืนยันบนเครื่อง"
ssh -p "$PORT" "${EXTRA[@]}" \
    -o IdentitiesOnly=yes -o IdentityFile="$HERE/speculos-test-key.pub" \
    -o UserKnownHostsFile="${KNOWN_HOSTS_FILE:-$D/known_hosts}" -o StrictHostKeyChecking=accept-new \
    -o BatchMode=yes -o ConnectTimeout=10 \
    "$(whoami)@127.0.0.1" 'echo "LOGIN-OK: $(whoami)@$(hostname)"'
