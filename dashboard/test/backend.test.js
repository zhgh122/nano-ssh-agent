// ทดสอบ backend ทั้งชุด (agent + monitor + server) กับ Ledger จำลอง
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { startBackend } = require('../backend');

function fakeLedger() {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    return {
        TRANSPORT: 'fake', APP_NAME: 'Nano SSH Agent', SSH_PATH: [44, 0x4c535348, 0, 0, 0],
        async getPublicKey() { return raw.toString('hex'); },
        async sign() { throw Object.assign(new Error('rejected'), { statusWord: '6985' }); },
        async deviceConnected() { return true; },
        async getAppAndVersion() { return { status: '9000', name: 'Nano SSH Agent', version: '0.1.0' }; },
        async close() {},
    };
}

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dash-')); }

async function call(b, method, p, body) {
    const res = await fetch(`http://127.0.0.1:${b.port}${p}`, {
        method,
        headers: { Authorization: `Bearer ${b.token}`, ...(body && { 'Content-Type': 'application/json' }) },
        body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, body: await res.json() };
}

test('agent stop/start through the API', async (t) => {
    const dir = tmp();
    const socketPath = path.join(dir, 'agent.sock');
    const b = await startBackend({ ledger: fakeLedger(), socketPath, historyPath: path.join(dir, 'h.jsonl'), pollMs: 50 });
    t.after(() => b.close());
    assert.strictEqual(b.agent.state().running, true);
    assert.ok(fs.existsSync(socketPath));

    const stopped = await call(b, 'POST', '/api/agent/stop', {});
    assert.strictEqual(stopped.status, 200);
    assert.strictEqual(stopped.body.running, false);
    assert.strictEqual(fs.existsSync(socketPath), false);

    const started = await call(b, 'POST', '/api/agent/start', {});
    assert.strictEqual(started.body.running, true);
    assert.ok(fs.existsSync(socketPath));
});

test('start reports a conflict when another agent owns the socket; dashboard still runs', async (t) => {
    const dir = tmp();
    const socketPath = path.join(dir, 'agent.sock');
    const other = net.createServer().listen(socketPath);
    await new Promise((r) => other.once('listening', r));
    t.after(() => other.close());

    const b = await startBackend({ ledger: fakeLedger(), socketPath, historyPath: path.join(dir, 'h.jsonl'), pollMs: 50 });
    t.after(() => b.close());
    assert.match(b.agentError, /another agent/);
    const r = await call(b, 'POST', '/api/agent/start', {});
    assert.strictEqual(r.status, 409);
    assert.match(r.body.error, /another agent/);
    assert.strictEqual((await call(b, 'GET', '/api/state')).body.agent.running, false);
});

test('there is no API that approves a signature', async (t) => {
    const dir = tmp();
    const b = await startBackend({ ledger: fakeLedger(), socketPath: path.join(dir, 'a.sock'),
        historyPath: path.join(dir, 'h.jsonl'), pollMs: 50 });
    t.after(() => b.close());
    for (const p of ['/api/approve', '/api/sign', '/api/button/both', '/api/agent/approve']) {
        assert.strictEqual((await call(b, 'POST', p, {})).status, 404, p);
    }
    const source = fs.readFileSync(path.join(__dirname, '..', 'backend.js'), 'utf8')
        + fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
    assert.doesNotMatch(source, /\/button\//, 'backend never talks to the Speculos button API');
});

test('add-key-command returns commands and validates input', async (t) => {
    const dir = tmp();
    const b = await startBackend({ ledger: fakeLedger(), socketPath: path.join(dir, 'a.sock'),
        historyPath: path.join(dir, 'h.jsonl'), pollMs: 50 });
    t.after(() => b.close());
    const ok = await call(b, 'POST', '/api/add-key-command', { user: 'ubuntu', host: '203.0.113.10', port: 2222 });
    assert.strictEqual(ok.status, 200);
    assert.match(ok.body.posix, /^ssh -p 2222 ubuntu@203\.0\.113\.10 '/);
    assert.match(ok.body.keyFingerprint, /^SHA256:/);
    const bad = await call(b, 'POST', '/api/add-key-command', { user: 'u', host: '$(reboot)', port: 22 });
    assert.strictEqual(bad.status, 400);
    assert.match(bad.body.error, /host/);
});
