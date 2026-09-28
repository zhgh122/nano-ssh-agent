// Dashboard backend: serve หน้าเว็บ + JSON API + Server-Sent Events ที่ 127.0.0.1 เท่านั้น
//
// ความปลอดภัย (เว็บอื่นในเบราว์เซอร์เดียวกันก็ยิงมาที่ localhost ได้):
// - listen เฉพาะ loopback
// - Host header ต้องเป็น localhost/127.0.0.1/[::1] (กัน DNS rebinding) ไม่เช็ก port
//   เพราะ port forward ของ VS Code อาจเปลี่ยนเลข port
// - ทุก /api ต้องมี token สุ่มต่อการเปิดหนึ่งครั้ง (ส่งให้หน้าเว็บผ่าน #fragment ของ URL)
// - POST ต้องมี Origin เป็น loopback (ถ้ามี) และ Content-Type JSON; ไม่มี CORS header
// - CSP default-src 'self': หน้าเว็บโหลดได้เฉพาะไฟล์จาก server นี้
// ไม่มี API ใดอนุมัติการเซ็นได้ การอนุมัติเกิดบนเครื่อง Ledger เท่านั้น
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const MAX_BODY = 16 * 1024;

const STATIC_FILES = {
    '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
    '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
    '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
    '/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' },
};

const SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        + "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Cross-Origin-Resource-Policy': 'same-origin',
};

function hostnameOf(hostHeader) {
    if (!hostHeader) return null;
    if (hostHeader.startsWith('[')) return hostHeader.slice(0, hostHeader.indexOf(']') + 1);
    return hostHeader.split(':')[0].toLowerCase();
}

function isLoopbackOrigin(origin) {
    try {
        const u = new URL(origin);
        return (u.protocol === 'http:' || u.protocol === 'https:') && LOOPBACK_HOSTS.has(u.hostname);
    } catch {
        return false;
    }
}

function safeEqual(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
    res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function readJson(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', (c) => {
            size += c.length;
            if (size > MAX_BODY) { reject(Object.assign(new Error('body too large'), { status: 413 })); req.destroy(); }
            else chunks.push(c);
        });
        req.on('end', () => {
            if (size === 0) return resolve({});
            try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
            catch { reject(Object.assign(new Error('invalid JSON'), { status: 400 })); }
        });
        req.on('error', reject);
    });
}

// routes: { 'GET /api/x': async ({ req, body, url }) => json }
function createDashboard({ agent, monitor, routes = {}, host = '127.0.0.1', port = 0,
                           token = crypto.randomBytes(24).toString('base64url'),
                           publicDir = path.join(__dirname, 'public') } = {}) {
    if (!LOOPBACK_HOSTS.has(host)) throw new Error(`refusing to listen on non-loopback address ${host}`);

    const clients = new Set();
    function broadcast(event, data) {
        const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
        for (const res of clients) res.write(msg);
    }
    const snapshot = () => ({ agent: agent.state(), device: monitor.status });
    const onState = () => broadcast('state', snapshot());
    agent.on('state', onState);
    monitor.on('status', onState);
    const heartbeat = setInterval(() => { for (const res of clients) res.write(': ping\n\n'); }, 15000);

    const allRoutes = {
        'GET /api/state': async () => snapshot(),
        ...routes,
    };

    const server = http.createServer(async (req, res) => {
        try {
            if (!LOOPBACK_HOSTS.has(hostnameOf(req.headers.host))) return send(res, 403, { error: 'bad host' });
            const url = new URL(req.url, 'http://localhost');

            if (!url.pathname.startsWith('/api/')) {
                const entry = req.method === 'GET' && STATIC_FILES[url.pathname];
                if (!entry) return send(res, 404, { error: 'not found' });
                return send(res, 200, fs.readFileSync(path.join(publicDir, entry.file)), entry.type);
            }

            // EventSource ตั้ง header เองไม่ได้ จึงรับ token ทาง query ได้เฉพาะ /api/events
            const auth = req.headers.authorization || '';
            const given = auth.startsWith('Bearer ') ? auth.slice(7)
                : (url.pathname === '/api/events' ? url.searchParams.get('token') : null);
            if (!given || !safeEqual(given, token)) return send(res, 401, { error: 'unauthorized' });

            if (req.method === 'POST') {
                if (req.headers.origin && !isLoopbackOrigin(req.headers.origin)) {
                    return send(res, 403, { error: 'bad origin' });
                }
                if (!(req.headers['content-type'] || '').startsWith('application/json')) {
                    return send(res, 415, { error: 'expected application/json' });
                }
            }

            if (req.method === 'GET' && url.pathname === '/api/events') {
                res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/event-stream', Connection: 'keep-alive' });
                res.write(`event: state\ndata: ${JSON.stringify(snapshot())}\n\n`);
                clients.add(res);
                req.on('close', () => clients.delete(res));
                return undefined;
            }

            const handler = allRoutes[`${req.method} ${url.pathname}`];
            if (!handler) return send(res, 404, { error: 'not found' });
            const body = req.method === 'POST' ? await readJson(req) : {};
            return send(res, 200, await handler({ req, url, body }));
        } catch (err) {
            if (!res.headersSent) send(res, err.status || 500, { error: err.message });
            else res.end();
        }
    });

    return {
        server,
        token,
        broadcast,
        listen() {
            return new Promise((resolve, reject) => {
                server.once('error', reject);
                server.listen(port, host, () => {
                    const actual = server.address().port;
                    resolve({ port: actual, url: `http://${host}:${actual}/#token=${token}` });
                });
            });
        },
        async close() {
            clearInterval(heartbeat);
            agent.off('state', onState);
            monitor.off('status', onState);
            for (const res of clients) res.end();
            await new Promise((resolve) => server.close(() => resolve()));
        },
    };
}

module.exports = { createDashboard, LOOPBACK_HOSTS };
