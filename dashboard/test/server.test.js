// ทดสอบความปลอดภัยและ API พื้นฐานของ dashboard server (ไม่ต้องมีเครื่อง)
// รัน: node --test dashboard/test/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { EventEmitter } = require('events');
const { createDashboard } = require('../server');

function fakes() {
    const agent = new EventEmitter();
    agent.st = { running: true, socketPath: '/tmp/x.sock', transport: 'fake', pending: null };
    agent.state = () => agent.st;
    const monitor = new EventEmitter();
    monitor.status = { connected: true, appOpen: true };
    return { agent, monitor };
}

async function start(extra = {}) {
    const { agent, monitor } = fakes();
    const d = createDashboard({ agent, monitor, ...extra });
    const { port } = await d.listen();
    return { d, agent, monitor, port };
}

// ส่ง request ดิบ (ตั้ง Host/Origin เองได้)
function req(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
        const r = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
            let data = '';
            res.on('data', (c) => { data += c; });
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        r.on('error', reject);
        if (body) r.write(body);
        r.end();
    });
}

test('refuses to listen on a non-loopback address', () => {
    const { agent, monitor } = fakes();
    assert.throws(() => createDashboard({ agent, monitor, host: '0.0.0.0' }), /non-loopback/);
});

test('listens on 127.0.0.1 only', async (t) => {
    const { d } = await start();
    t.after(() => d.close());
    assert.strictEqual(d.server.address().address, '127.0.0.1');
});

test('static page is served with security headers', async (t) => {
    const { d, port } = await start();
    t.after(() => d.close());
    const r = await req(port, { headers: { Host: `127.0.0.1:${port}` } });
    assert.strictEqual(r.status, 200);
    assert.match(r.headers['content-security-policy'], /default-src 'self'/);
    assert.strictEqual(r.headers['x-frame-options'], 'DENY');
    assert.strictEqual(r.headers['access-control-allow-origin'], undefined);
});

test('rejects foreign Host headers (DNS rebinding) but accepts any loopback port', async (t) => {
    const { d, port } = await start();
    t.after(() => d.close());
    assert.strictEqual((await req(port, { headers: { Host: 'evil.example:80' } })).status, 403);
    assert.strictEqual((await req(port, { headers: { Host: '127.0.0.1.evil.example' } })).status, 403);
    assert.strictEqual((await req(port, { headers: { Host: 'localhost:55555' } })).status, 200);
});

test('only whitelisted static files, no path traversal', async (t) => {
    const { d, port } = await start();
    t.after(() => d.close());
    for (const path of ['/../server.js', '/%2e%2e/server.js', '/server.js', '/public/app.js']) {
        assert.strictEqual((await req(port, { path, headers: { Host: 'localhost' } })).status, 404, path);
    }
});

test('API needs the token; query token only accepted for /api/events', async (t) => {
    const { d, port } = await start();
    t.after(() => d.close());
    const h = { Host: 'localhost' };
    assert.strictEqual((await req(port, { path: '/api/state', headers: h })).status, 401);
    assert.strictEqual((await req(port, { path: '/api/state', headers: { ...h, Authorization: 'Bearer nope' } })).status, 401);
    assert.strictEqual((await req(port, { path: `/api/state?token=${d.token}`, headers: h })).status, 401);
    const ok = await req(port, { path: '/api/state', headers: { ...h, Authorization: `Bearer ${d.token}` } });
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(JSON.parse(ok.body).agent.running, true);
});

test('POST: foreign Origin and non-JSON content type are refused', async (t) => {
    const routes = { 'POST /api/echo': async ({ body }) => body };
    const { d, port } = await start({ routes });
    t.after(() => d.close());
    const h = { Host: 'localhost', Authorization: `Bearer ${d.token}` };
    assert.strictEqual((await req(port, { method: 'POST', path: '/api/echo',
        headers: { ...h, Origin: 'https://evil.example', 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
    assert.strictEqual((await req(port, { method: 'POST', path: '/api/echo',
        headers: { ...h, 'Content-Type': 'text/plain' }, body: '{}' })).status, 415);
    const ok = await req(port, { method: 'POST', path: '/api/echo',
        headers: { ...h, Origin: 'http://localhost:1234', 'Content-Type': 'application/json' }, body: '{"a":1}' });
    assert.deepStrictEqual(JSON.parse(ok.body), { a: 1 });
});

test('SSE sends the state at once and on every change', async (t) => {
    const { d, agent, port } = await start();
    t.after(() => d.close());
    const events = [];
    await new Promise((resolve, reject) => {
        const r = http.get({ host: '127.0.0.1', port, path: `/api/events?token=${d.token}`, headers: { Host: 'localhost' } },
            (res) => {
                res.on('data', (c) => {
                    for (const m of String(c).matchAll(/data: (.*)\n/g)) events.push(JSON.parse(m[1]));
                    if (events.length === 1) {
                        agent.st = { ...agent.st, pending: { since: 'now' } };
                        agent.emit('state', agent.st);
                    }
                    if (events.length === 2) { r.destroy(); resolve(); }
                });
            });
        r.on('error', reject);
    });
    assert.strictEqual(events[0].agent.pending, null);
    assert.deepStrictEqual(events[1].agent.pending, { since: 'now' });
});
