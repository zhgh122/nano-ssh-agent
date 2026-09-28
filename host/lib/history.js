// ประวัติการเซ็นเก็บเป็น JSON ทีละบรรทัดในเครื่องผู้ใช้
// เก็บเฉพาะ: เวลา, ชนิด, user, server (ชื่อ/fingerprint ของ host key), fingerprint ของ key เรา,
// ผลลัพธ์ และรหัส error — ห้ามเก็บลายเซ็น ข้อมูลที่เซ็น หรือ session id
const fs = require('fs');
const os = require('os');
const path = require('path');

const MAX_BYTES = 2 * 1024 * 1024;   // เกินนี้เหลือไว้ KEEP_AFTER_ROTATE รายการล่าสุด
const KEEP_AFTER_ROTATE = 1000;

function defaultHistoryPath() {
    if (process.env.NANO_SSH_AGENT_HISTORY) return process.env.NANO_SSH_AGENT_HISTORY;
    let base;
    if (process.platform === 'win32') base = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    else if (process.platform === 'darwin') base = path.join(os.homedir(), 'Library', 'Application Support');
    else base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    return path.join(base, 'nano-ssh-agent', 'history.jsonl');
}

const ALLOWED_FIELDS = ['time', 'kind', 'user', 'namespace', 'server', 'keyFingerprint', 'result', 'error'];
const ALLOWED_SERVER_FIELDS = ['names', 'hashedMatches', 'type', 'fingerprint', 'forwarded'];

// รับเฉพาะ field ที่อนุญาต กันการเผลอบันทึกข้อมูลดิบในอนาคต
function sanitize(entry) {
    const out = {};
    for (const k of ALLOWED_FIELDS) if (entry[k] !== undefined && entry[k] !== null) out[k] = entry[k];
    if (entry.server) {
        out.server = {};
        for (const k of ALLOWED_SERVER_FIELDS) if (entry.server[k] !== undefined) out.server[k] = entry.server[k];
    }
    return out;
}

class History {
    constructor(file = defaultHistoryPath()) {
        this.file = file;
    }

    append(entry) {
        const clean = sanitize(entry);
        fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
        fs.appendFileSync(this.file, `${JSON.stringify(clean)}\n`, { mode: 0o600 });
        this.rotateIfNeeded();
        return clean;
    }

    rotateIfNeeded() {
        let size = 0;
        try { size = fs.statSync(this.file).size; } catch { return; }
        if (size <= MAX_BYTES) return;
        const keep = this.readAll().slice(-KEEP_AFTER_ROTATE);
        const tmp = `${this.file}.tmp`;
        fs.writeFileSync(tmp, keep.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
        fs.renameSync(tmp, this.file);
    }

    readAll() {
        let text;
        try { text = fs.readFileSync(this.file, 'utf8'); } catch { return []; }
        const out = [];
        for (const line of text.split('\n')) {
            if (!line.trim()) continue;
            try { out.push(JSON.parse(line)); } catch { /* ข้ามบรรทัดเสีย */ }
        }
        return out;
    }

    // ล่าสุดก่อน
    recent(limit = 100) {
        return this.readAll().slice(-limit).reverse();
    }
}

module.exports = { History, defaultHistoryPath, sanitize };
