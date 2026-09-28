// แกะข้อมูลที่ถูกส่งมาให้เซ็น เพื่อบอกผู้ใช้ว่ากำลังเซ็นอะไร (ใช้แสดงผลและบันทึกประวัติเท่านั้น)
// - SSH_MSG_USERAUTH_REQUEST (RFC 4252 §7): session id, user, service, method, key
//   รวมแบบ publickey-hostbound-v00@openssh.com ที่มี host key ต่อท้าย
// - SSHSIG (ssh-keygen -Y sign): namespace
// - session-bind@openssh.com: host key ของ server + ลายเซ็นของ server บน session id
//   ตรวจลายเซ็นก่อนเชื่อ เพื่อไม่ให้ client ปลอมชื่อ server ได้
const crypto = require('crypto');
const { Reader } = require('./ssh-wire');
const { fingerprint } = require('./ssh-key');

const SSH_MSG_USERAUTH_REQUEST = 50;
const SSHSIG_MAGIC = Buffer.from('SSHSIG');

function parseUserauthRequest(data) {
    const r = new Reader(data);
    const sessionId = r.string();
    if (r.byte() !== SSH_MSG_USERAUTH_REQUEST) return null;
    const user = r.text();
    const service = r.text();
    const method = r.text();
    if (method !== 'publickey' && method !== 'publickey-hostbound-v00@openssh.com') return null;
    if (!r.bool()) return null;
    const algorithm = r.text();
    const keyBlob = r.string();
    const hostKey = method === 'publickey-hostbound-v00@openssh.com' ? r.string() : null;
    if (!r.done()) return null;
    return { sessionId, user, service, method, algorithm, keyBlob, hostKey };
}

function parseSshsig(data) {
    if (data.length < 6 || !data.subarray(0, 6).equals(SSHSIG_MAGIC)) return null;
    const r = new Reader(data.subarray(6));
    const namespace = r.text();
    r.string();              // reserved
    const hashAlgorithm = r.text();
    r.string();              // H(message)
    if (!r.done()) return null;
    return { namespace, hashAlgorithm };
}

// body ของ SSH_AGENTC_EXTENSION หลังชื่อ extension
function parseSessionBind(r) {
    const hostKey = r.string();
    const sessionId = r.string();
    const signature = r.string();
    const forwarding = r.bool();
    if (!r.done()) throw new Error('bad session-bind');
    return { hostKey, sessionId, signature, forwarding };
}

function stripMpint(b) {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
}

const b64url = (b) => Buffer.from(b).toString('base64url');

const ECDSA = {
    nistp256: { crv: 'P-256', size: 32, hash: 'sha256' },
    nistp384: { crv: 'P-384', size: 48, hash: 'sha384' },
    nistp521: { crv: 'P-521', size: 66, hash: 'sha512' },
};
const RSA_SIG_HASH = { 'rsa-sha2-256': 'sha256', 'rsa-sha2-512': 'sha512', 'ssh-rsa': 'sha1' };

// ตรวจว่า signature (รูปแบบ SSH) เป็นลายเซ็นของ hostKey บน data จริง; ชนิดที่ไม่รองรับคืน false
function verifySshSignature(hostKey, data, signature) {
    try {
        const k = new Reader(hostKey);
        const keyType = k.text();
        const s = new Reader(signature);
        const sigType = s.text();
        const sig = s.string();
        if (!s.done()) return false;

        if (keyType === 'ssh-ed25519') {
            const pub = k.string();
            if (!k.done() || sigType !== 'ssh-ed25519' || pub.length !== 32) return false;
            const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(pub) }, format: 'jwk' });
            return crypto.verify(null, data, key, sig);
        }

        if (keyType.startsWith('ecdsa-sha2-')) {
            const curveName = k.text();
            const q = k.string();
            const c = ECDSA[curveName];
            if (!k.done() || !c || sigType !== keyType || q.length !== 1 + 2 * c.size || q[0] !== 4) return false;
            const key = crypto.createPublicKey({
                key: { kty: 'EC', crv: c.crv, x: b64url(q.subarray(1, 1 + c.size)), y: b64url(q.subarray(1 + c.size)) },
                format: 'jwk',
            });
            const rs = new Reader(sig);
            const rr = stripMpint(rs.string());
            const ss = stripMpint(rs.string());
            if (!rs.done() || rr.length > c.size || ss.length > c.size) return false;
            const p1363 = Buffer.concat([Buffer.alloc(c.size - rr.length), rr, Buffer.alloc(c.size - ss.length), ss]);
            return crypto.verify(c.hash, data, { key, dsaEncoding: 'ieee-p1363' }, p1363);
        }

        if (keyType === 'ssh-rsa') {
            const e = stripMpint(k.string());
            const n = stripMpint(k.string());
            const hash = RSA_SIG_HASH[sigType];
            if (!k.done() || !hash) return false;
            const key = crypto.createPublicKey({ key: { kty: 'RSA', n: b64url(n), e: b64url(e) }, format: 'jwk' });
            return crypto.verify(hash, data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
        }
        return false;
    } catch {
        return false;
    }
}

function hostKeyInfo(hostKey) {
    let type = 'unknown';
    try { type = new Reader(hostKey).text(); } catch { /* ignore */ }
    return { type, fingerprint: fingerprint(hostKey) };
}

// สรุปคำขอเซ็นสำหรับแสดงผล: ไม่มี session id, ไม่มีข้อมูลดิบ
// verifiedBinds: Map<sessionIdHex, { hostKey, forwarding }> จาก session-bind ที่ตรวจลายเซ็นผ่านแล้ว
function describeSignRequest(data, verifiedBinds = new Map()) {
    let ua = null;
    try { ua = parseUserauthRequest(data); } catch { ua = null; }
    if (ua) {
        const bind = verifiedBinds.get(ua.sessionId.toString('hex'));
        return {
            kind: 'ssh-login',
            user: ua.user,
            service: ua.service,
            server: bind ? { ...hostKeyInfo(bind.hostKey), forwarded: bind.forwarding } : null,
            serverHostKey: bind ? bind.hostKey : null,   // ใช้หาชื่อใน known_hosts แล้วทิ้ง ไม่บันทึก
        };
    }
    let sig = null;
    try { sig = parseSshsig(data); } catch { sig = null; }
    if (sig) return { kind: 'sshsig', namespace: sig.namespace, user: null, server: null, serverHostKey: null };
    return { kind: 'unknown', user: null, server: null, serverHostKey: null };
}

module.exports = {
    parseUserauthRequest,
    parseSshsig,
    parseSessionBind,
    verifySshSignature,
    hostKeyInfo,
    describeSignRequest,
};
