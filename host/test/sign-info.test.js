const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { sshString, uint32 } = require('../lib/ssh-wire');
const {
    parseUserauthRequest, parseSshsig, verifySshSignature, describeSignRequest,
} = require('../lib/sign-info');
const { lookupHostKey } = require('../lib/known-hosts');
const { History, sanitize } = require('../lib/history');
const { fingerprint } = require('../lib/ssh-key');

const s = (x) => sshString(Buffer.from(x));
const mpint = (b) => sshString(b[0] & 0x80 ? Buffer.concat([Buffer.alloc(1), b]) : b);

// ---- host key ของ server จำลอง ในรูปแบบ SSH (blob + ฟังก์ชันเซ็นแบบ sshd)
function hostKey(kind) {
    if (kind === 'ed25519') {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const x = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
        return {
            blob: Buffer.concat([s('ssh-ed25519'), sshString(x)]),
            sign: (d) => Buffer.concat([s('ssh-ed25519'), sshString(crypto.sign(null, d, privateKey))]),
        };
    }
    if (kind.startsWith('nistp')) {
        const c = { nistp256: ['prime256v1', 'sha256', 32], nistp384: ['secp384r1', 'sha384', 48], nistp521: ['secp521r1', 'sha512', 66] }[kind];
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: c[0] });
        const jwk = publicKey.export({ format: 'jwk' });
        const q = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
        const type = `ecdsa-sha2-${kind}`;
        return {
            blob: Buffer.concat([s(type), s(kind), sshString(q)]),
            sign: (d) => {
                const raw = crypto.sign(c[1], d, { key: privateKey, dsaEncoding: 'ieee-p1363' });
                const r = raw.subarray(0, c[2]);
                const sv = raw.subarray(c[2]);
                return Buffer.concat([s(type), sshString(Buffer.concat([mpint(r), mpint(sv)]))]);
            },
        };
    }
    // RSA กับ rsa-sha2-256/512
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const alg = kind;
    const hash = alg === 'rsa-sha2-512' ? 'sha512' : 'sha256';
    return {
        blob: Buffer.concat([s('ssh-rsa'), mpint(Buffer.from(jwk.e, 'base64url')), mpint(Buffer.from(jwk.n, 'base64url'))]),
        sign: (d) => Buffer.concat([s(alg), sshString(crypto.sign(hash, d, privateKey))]),
    };
}

function userauth({ sessionId, user = 'alice', method = 'publickey', hostKeyBlob = null }) {
    const keyBlob = Buffer.concat([s('ssh-ed25519'), sshString(Buffer.alloc(32, 1))]);
    return Buffer.concat([
        sshString(sessionId), Buffer.from([50]), s(user), s('ssh-connection'), s(method),
        Buffer.from([1]), s('ssh-ed25519'), sshString(keyBlob),
        ...(hostKeyBlob ? [sshString(hostKeyBlob)] : []),
    ]);
}

test('parses a publickey userauth request', () => {
    const sid = crypto.randomBytes(32);
    const ua = parseUserauthRequest(userauth({ sessionId: sid, user: 'ubuntu' }));
    assert.strictEqual(ua.user, 'ubuntu');
    assert.strictEqual(ua.service, 'ssh-connection');
    assert.deepStrictEqual(ua.sessionId, sid);
    assert.strictEqual(ua.hostKey, null);
});

test('parses the hostbound variant and rejects other data', () => {
    const hk = hostKey('ed25519');
    const ua = parseUserauthRequest(userauth({ sessionId: Buffer.alloc(32), method: 'publickey-hostbound-v00@openssh.com', hostKeyBlob: hk.blob }));
    assert.deepStrictEqual(ua.hostKey, hk.blob);
    assert.strictEqual(parseUserauthRequest(Buffer.concat([sshString(Buffer.alloc(32)), Buffer.from([51])])), null);
    assert.throws(() => parseUserauthRequest(Buffer.from([0, 0, 0, 40, 1])), /truncated/);
});

test('parses SSHSIG', () => {
    const data = Buffer.concat([Buffer.from('SSHSIG'), s('file'), s(''), s('sha512'), sshString(Buffer.alloc(64))]);
    assert.deepStrictEqual(parseSshsig(data), { namespace: 'file', hashAlgorithm: 'sha512' });
    assert.strictEqual(parseSshsig(Buffer.from('nope')), null);
});

for (const kind of ['ed25519', 'nistp256', 'nistp384', 'nistp521', 'rsa-sha2-256', 'rsa-sha2-512']) {
    test(`verifies a ${kind} host key signature over the session id, rejects tampering`, () => {
        const hk = hostKey(kind);
        const sid = crypto.randomBytes(32);
        const sig = hk.sign(sid);
        assert.strictEqual(verifySshSignature(hk.blob, sid, sig), true);
        const other = Buffer.from(sid); other[0] ^= 1;
        assert.strictEqual(verifySshSignature(hk.blob, other, sig), false);
        assert.strictEqual(verifySshSignature(hostKey('ed25519').blob, sid, sig), false);
    });
}

test('describeSignRequest only names the server when a verified bind matches the session', () => {
    const hk = hostKey('ed25519');
    const sid = crypto.randomBytes(32);
    const data = userauth({ sessionId: sid, user: 'bob' });
    const none = describeSignRequest(data, new Map());
    assert.strictEqual(none.user, 'bob');
    assert.strictEqual(none.server, null);
    const binds = new Map([[sid.toString('hex'), { hostKey: hk.blob, forwarding: false }]]);
    const withBind = describeSignRequest(data, binds);
    assert.strictEqual(withBind.server.fingerprint, fingerprint(hk.blob));
    assert.strictEqual(withBind.server.type, 'ssh-ed25519');
    assert.deepStrictEqual(describeSignRequest(Buffer.from('random'), binds).kind, 'unknown');
});

test('known_hosts lookup: plain names, hashed entries, markers and negations', () => {
    const hk = hostKey('ed25519');
    const other = hostKey('ed25519');
    const b64 = hk.blob.toString('base64');
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kh-')), 'known_hosts');
    fs.writeFileSync(f, [
        '# comment',
        `server1.example,10.0.0.5,!bad.example ssh-ed25519 ${b64}`,
        `|1|c2FsdA==|aGFzaA== ssh-ed25519 ${b64}`,
        `@revoked revoked.example ssh-ed25519 ${b64}`,
        `[host]:2222 ssh-ed25519 ${other.blob.toString('base64')}`,
        '',
    ].join('\r\n'));
    assert.deepStrictEqual(lookupHostKey(hk.blob, [f, '/nonexistent']), { names: ['server1.example', '10.0.0.5'], hashedMatches: 1 });
    assert.deepStrictEqual(lookupHostKey(hostKey('ed25519').blob, [f]), { names: [], hashedMatches: 0 });
});

test('history keeps only allowed fields, newest first, file mode 0600', () => {
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hist-')), 'sub', 'history.jsonl');
    const h = new History(f);
    h.append({ time: 't1', kind: 'ssh-login', user: 'a', result: 'approved', signature: 'SECRET', data: 'RAW',
        server: { names: ['x'], fingerprint: 'SHA256:x', sessionId: 'SID' } });
    h.append({ time: 't2', kind: 'ssh-login', user: 'b', result: 'rejected' });
    const text = fs.readFileSync(f, 'utf8');
    assert.doesNotMatch(text, /SECRET|RAW|SID/);
    assert.deepStrictEqual(h.recent().map((e) => e.time), ['t2', 't1']);
    assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
    assert.deepStrictEqual(sanitize({ user: 'u', error: null }), { user: 'u' });
});
