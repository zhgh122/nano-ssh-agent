// สร้าง "คำสั่งให้ผู้ใช้ copy ไปรันเอง" เพื่อเพิ่ม public key ลง authorized_keys ของ server
// โปรแกรมนี้ไม่รันคำสั่งเหล่านี้เอง และไม่เชื่อมต่อ server ใด ๆ
//
// ความปลอดภัยของคำสั่งที่สร้าง:
// - user/host/port ต้องผ่าน whitelist ตัวอักษร (กันการแทรกคำสั่ง เช่น $(...), ;, -oProxyCommand)
// - key ต้องเป็นบรรทัด ssh-ed25519 ที่มีแต่ตัวอักษร base64 (ใส่ในเครื่องหมายคำพูดได้ปลอดภัย)
// - บน server: ไม่ลบ key เดิม, ไม่เพิ่มซ้ำ, เติม newline ถ้าไฟล์เดิมไม่มี, สิทธิ์ 700/600

const USER_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV6_RE = /^[0-9A-Fa-f:.]{2,45}$/;
const KEY_LINE_RE = /^ssh-ed25519 [A-Za-z0-9+/]+={0,2} [A-Za-z0-9._@-]{1,64}$/;

function validate({ user, host, port }) {
    const errors = [];
    if (typeof user !== 'string' || !USER_RE.test(user)) errors.push('user: only A-Z a-z 0-9 . _ - allowed (must not start with - or .)');
    const h = typeof host === 'string' ? host.replace(/^\[(.*)\]$/, '$1') : '';
    const isIpv6 = h.includes(':');
    if (!(isIpv6 ? IPV6_RE.test(h) : HOSTNAME_RE.test(h))) errors.push('host: must be a host name or IP address');
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) errors.push('port: must be a number from 1 to 65535');
    return { errors, user, host: h, port: p };
}

// สคริปต์ที่รันบน server (POSIX sh)
function remoteScript(keyLine) {
    return [
        'umask 077',
        'mkdir -p ~/.ssh',
        'f=~/.ssh/authorized_keys',
        `k="${keyLine}"`,
        'touch "$f"',
        'if grep -qxF "$k" "$f"; then echo "nano-ssh-agent: key already authorized"; else',
        '  if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi',
        '  echo "$k" >> "$f"; echo "nano-ssh-agent: key added"',
        'fi',
    ];
}

function buildAddKeyCommands({ user, host, port = 22, keyLine, socketPath }) {
    const v = validate({ user, host, port });
    if (v.errors.length) throw Object.assign(new Error(v.errors.join('\n')), { status: 400 });
    if (typeof keyLine !== 'string' || !KEY_LINE_RE.test(keyLine)) {
        throw Object.assign(new Error('key is not an ssh-ed25519 line in the expected format'), { status: 400 });
    }
    const target = `${v.user}@${v.host.includes(':') ? `[${v.host}]` : v.host}`;
    const portOpt = v.port === 22 ? '' : ` -p ${v.port}`;
    const lines = remoteScript(keyLine);

    // POSIX shell (Linux/macOS): สคริปต์ทั้งก้อนอยู่ใน '...' ส่งให้ ssh เป็นคำสั่งฝั่ง server
    const posix = `ssh${portOpt} ${target} '${lines.join('\n')}'`;

    // PowerShell (Windows): ส่งสคริปต์ทาง stdin ด้วย here-string แบบ '...' (ไม่แปลงตัวแปร)
    // tr ลบ \r ที่ PowerShell เติมท้ายบรรทัด
    const powershell = `@'\n${lines.join('\n')}\n'@ | ssh${portOpt} ${target} "tr -d '\\r' | sh"`;

    // path ของ socket มาจากการตั้งค่าในเครื่อง ใส่ใน '...' ได้ถ้าไม่มี ' อยู่ในนั้น
    const sock = socketPath && !socketPath.includes("'") ? socketPath : null;
    const testPosix = `SSH_AUTH_SOCK='${sock || '/tmp/nano-ssh-agent.sock'}' ssh${portOpt} ${target}`;
    const testPowershell = `$env:SSH_AUTH_SOCK = '${sock || '\\\\.\\pipe\\nano-ssh-agent'}'; ssh${portOpt} ${target}`;

    return { target, posix, powershell, testPosix, testPowershell };
}

module.exports = { buildAddKeyCommands, validate, remoteScript };
