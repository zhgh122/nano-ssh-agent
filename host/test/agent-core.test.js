// ทดสอบ agent-core กับ Ledger จำลอง (ไม่ต้องมี Speculos)
// รัน: node --test host/test/
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { LedgerAgent } = require('../lib/agent-core');
const { sshString, uint32, Reader } = require('../lib/ssh-wire');

// Ledger จำลอง: key ed25519 จริงใน memory, ผลการกดกำหนดได้
function fakeLedger() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const fake = {
        TRANSPORT: 'fake',
        SSH_PATH: [44, 0x4c535348, 0, 0, 0],
        answer: 'approve',             // approve | reject
        signCalls: 0,
        async getPublicKey() { return raw.toString('hex'); },
        async sign(p, data) {
            fake.signCalls++;
            await new Promise((r) => setTimeout(r, 20));
            if (fake.answer === 'reject') {
                throw Object.assign(new Error('Ledger error: 6985 (rejected on device)'), { statusWord: '6985' });
            }
            return crypto.sign(null, data, privateKey).toString('hex');
        },
        async close() {},
        raw,
        publicKey,
    };
    return fake;
}

function tmpSock() {
    return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'agent-test-')), 'agent.sock');
}

// ส่งคำขอหลายอัน (ต่อกันเป็นก้อนเดียวได้) แล้วรอรับคำตอบครบ n อัน
function request(sockPath, payloads, { byteByByte = false } = {}) {
    return new Promise((resolve, reject) => {
        const c = net.connect(sockPath);
        let buf = Buffer.alloc(0);
        const replies = [];
        c.on('data', (d) => {
            buf = Buffer.concat([buf, d]);
            while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
                const len = buf.readUInt32BE(0);
                replies.push(buf.subarray(4, 4 + len));
                buf = buf.subarray(4 + len);
            }
            if (replies.length === payloads.length) { c.end(); resolve(replies); }
        });
        c.on('error', reject);
        c.on('connect', async () => {
            const all = Buffer.concat(payloads.map((p) => sshString(p)));
            if (!byteByByte) return c.write(all);
            for (const b of all) { c.write(Buffer.from([b])); await new Promise((r) => setImmediate(r)); }
        });
    });
}

const REQUEST_IDENTITIES = Buffer.from([11]);
function signRequest(blob, data) {
    return Buffer.concat([Buffer.from([13]), sshString(blob), sshString(data), uint32(0)]);
}

test('lists the Ledger key and signs after approval', async (t) => {
    const ledger = fakeLedger();
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock() });
    await agent.start();
    t.after(() => agent.stop());

    const [ids] = await request(agent.socketPath, [REQUEST_IDENTITIES]);
    const r = new Reader(ids);
    assert.strictEqual(r.byte(), 12);
    assert.strictEqual(r.uint32(), 1);
    const blob = r.string();
    assert.strictEqual(r.text(), 'ledger');
    assert.deepStrictEqual(blob, LedgerAgent.keyBlob(ledger.raw));

    const data = Buffer.from('data to sign');
    const [resp] = await request(agent.socketPath, [signRequest(blob, data)]);
    const s = new Reader(resp);
    assert.strictEqual(s.byte(), 14);
    const sigBlob = new Reader(s.string());
    assert.strictEqual(sigBlob.text(), 'ssh-ed25519');
    assert.ok(crypto.verify(null, data, ledger.publicKey, sigBlob.string()));
});

test('rejection on the device gives SSH_AGENT_FAILURE', async (t) => {
    const ledger = fakeLedger();
    ledger.answer = 'reject';
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock() });
    await agent.start();
    t.after(() => agent.stop());
    const [resp] = await request(agent.socketPath, [signRequest(LedgerAgent.keyBlob(ledger.raw), Buffer.from('x'))]);
    assert.deepStrictEqual([...resp], [5]);
});

test('unknown key, malformed and unsupported requests fail without touching the device', async (t) => {
    const ledger = fakeLedger();
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock() });
    await agent.start();
    t.after(() => agent.stop());
    const otherBlob = LedgerAgent.keyBlob(Buffer.alloc(32, 7));
    const replies = await request(agent.socketPath, [
        signRequest(otherBlob, Buffer.from('x')),
        Buffer.from([13, 0, 0, 0, 9]),          // truncated
        Buffer.from([99]),                      // unknown type
    ]);
    assert.deepStrictEqual(replies.map((r) => [...r]), [[5], [5], [5]]);
    assert.strictEqual(ledger.signCalls, 0);
});

test('handles byte-by-byte input and pipelined requests in order', async (t) => {
    const ledger = fakeLedger();
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock() });
    await agent.start();
    t.after(() => agent.stop());
    const replies = await request(agent.socketPath,
        [REQUEST_IDENTITIES, Buffer.from([99]), REQUEST_IDENTITIES], { byteByByte: true });
    assert.deepStrictEqual(replies.map((r) => r[0]), [12, 5, 12]);
});

test('reports pending approval while the device is signing', async (t) => {
    const ledger = fakeLedger();
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock() });
    const states = [];
    agent.on('state', (s) => states.push(s.pending !== null));
    await agent.start();
    t.after(() => agent.stop());
    await request(agent.socketPath, [signRequest(LedgerAgent.keyBlob(ledger.raw), Buffer.from('x'))]);
    assert.ok(states.includes(true), 'pending was reported');
    assert.strictEqual(states.at(-1), false, 'pending cleared at the end');
});

test('start/stop: socket is 0600, removed on stop, and a live socket is not stolen', async () => {
    const ledger = fakeLedger();
    const sock = tmpSock();
    const a = new LedgerAgent({ ledger, socketPath: sock });
    await a.start();
    assert.strictEqual(fs.statSync(sock).mode & 0o777, 0o600);
    assert.strictEqual(a.state().running, true);

    const b = new LedgerAgent({ ledger, socketPath: sock });
    await assert.rejects(b.start(), /another agent is already listening/);
    assert.strictEqual(b.state().running, false);

    await a.stop();
    assert.strictEqual(fs.existsSync(sock), false);
    assert.strictEqual(a.state().running, false);

    // socket ค้าง (ไม่มีใครฟัง) ต้องถูกแทนที่ได้
    fs.writeFileSync(sock, '');
    await b.start();
    assert.strictEqual(b.state().running, true);
    await b.stop();
});

test('session-bind: a valid host key signature names the server; a forged one is ignored', async (t) => {
    const ledger = fakeLedger();
    const hk = crypto.generateKeyPairSync('ed25519');
    const hkRaw = Buffer.from(hk.publicKey.export({ format: 'jwk' }).x, 'base64url');
    const hkBlob = Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(hkRaw)]);
    const resolved = [];
    const agent = new LedgerAgent({ ledger, socketPath: tmpSock(),
        resolveHostKey: (blob) => { resolved.push(blob); return { names: ['myserver'], hashedMatches: 0 }; } });
    const ends = [];
    agent.on('sign-end', (e) => ends.push(e));
    await agent.start();
    t.after(() => agent.stop());

    const bind = (sid, sigOver) => Buffer.concat([Buffer.from([27]), sshString(Buffer.from('session-bind@openssh.com')),
        sshString(hkBlob), sshString(sid),
        sshString(Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(crypto.sign(null, sigOver, hk.privateKey))])),
        Buffer.from([0])]);
    const userauth = (sid) => Buffer.concat([sshString(sid), Buffer.from([50]), sshString(Buffer.from('ubuntu')),
        sshString(Buffer.from('ssh-connection')), sshString(Buffer.from('publickey')), Buffer.from([1]),
        sshString(Buffer.from('ssh-ed25519')), sshString(LedgerAgent.keyBlob(ledger.raw))]);
    const blob = LedgerAgent.keyBlob(ledger.raw);

    const sid = crypto.randomBytes(32);
    const [bindOk, signOk] = await request(agent.socketPath, [bind(sid, sid), signRequest(blob, userauth(sid))]);
    assert.deepStrictEqual([...bindOk], [6]);
    assert.strictEqual(signOk[0], 14);

    const sid2 = crypto.randomBytes(32);
    const [bindBad] = await request(agent.socketPath, [bind(sid2, Buffer.from('not the session id'))]);
    assert.deepStrictEqual([...bindBad], [5]);

    ledger.answer = 'reject';
    await request(agent.socketPath, [signRequest(blob, userauth(sid2))]);

    assert.strictEqual(ends.length, 2);
    assert.strictEqual(ends[0].result, 'approved');
    assert.strictEqual(ends[0].request.user, 'ubuntu');
    assert.deepStrictEqual(ends[0].request.server.names, ['myserver']);
    assert.strictEqual(ends[1].result, 'rejected');
    assert.strictEqual(ends[1].request.server, null, 'forged bind must not name the server');
    assert.strictEqual(resolved.length, 1);
    for (const e of ends) {
        assert.strictEqual(JSON.stringify(e).includes(sid.toString('hex')), false, 'no session id in events');
    }
});
