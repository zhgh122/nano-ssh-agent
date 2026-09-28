// หาว่า host key ของ server อยู่ใน known_hosts ภายใต้ชื่ออะไร
// - บรรทัดแบบ hashed (|1|salt|hash) ย้อนกลับเป็นชื่อไม่ได้: บอกได้แค่ว่า "รู้จัก key นี้"
// - ข้าม @revoked และ @cert-authority
const fs = require('fs');
const os = require('os');
const path = require('path');

function defaultKnownHostsFiles() {
    if (process.env.KNOWN_HOSTS_FILES) return process.env.KNOWN_HOSTS_FILES.split(path.delimiter).filter(Boolean);
    const home = os.homedir();
    const files = [path.join(home, '.ssh', 'known_hosts'), path.join(home, '.ssh', 'known_hosts2')];
    if (process.platform === 'win32') {
        files.push(path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'ssh', 'ssh_known_hosts'));
    } else {
        files.push('/etc/ssh/ssh_known_hosts', '/etc/ssh/ssh_known_hosts2');
    }
    return files;
}

// คืน { names: [...ชื่อที่อ่านได้], hashedMatches: จำนวนบรรทัด hashed ที่ key ตรง }
function lookupHostKey(hostKeyBlob, files = defaultKnownHostsFiles()) {
    const wanted = hostKeyBlob.toString('base64');
    const names = new Set();
    let hashedMatches = 0;
    for (const file of files) {
        let text;
        try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
        for (const raw of text.split(/\r?\n/)) {
            const line = raw.trim();
            if (!line || line.startsWith('#')) continue;
            const fields = line.split(/\s+/);
            if (fields[0].startsWith('@')) continue;       // @revoked / @cert-authority
            const [hosts, , keyB64] = fields;
            if (keyB64 !== wanted) continue;
            for (const h of hosts.split(',')) {
                if (h.startsWith('|1|')) hashedMatches++;
                else if (!h.startsWith('!')) names.add(h);
            }
        }
    }
    return { names: [...names], hashedMatches };
}

module.exports = { defaultKnownHostsFiles, lookupHostKey };
