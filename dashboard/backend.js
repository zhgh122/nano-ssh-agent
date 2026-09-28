// ประกอบ agent + ตัวตรวจสถานะเครื่อง + HTTP server เข้าด้วยกัน
// ใช้ทั้งจาก cli.js (เปิดผ่านเบราว์เซอร์) และ electron/main.js
const { requireHost } = require('./host-path');

const { LedgerAgent } = requireHost('lib/agent-core');
const { DeviceMonitor } = requireHost('lib/device-status');
const { authorizedKeyLine, fingerprint, ed25519Blob } = requireHost('lib/ssh-key');
const { History } = requireHost('lib/history');
const { buildAddKeyCommands } = requireHost('lib/add-key-command');
const { createDashboard } = require('./server');

async function startBackend({ port = 0, startAgent = true, ledger, socketPath, historyPath, pollMs = 2000,
                             log = () => {} } = {}) {
    const agent = new LedgerAgent({ ...(ledger && { ledger }), ...(socketPath && { socketPath }) });
    const history = new History(historyPath);
    agent.on('log', log);
    const monitor = new DeviceMonitor({ agent, intervalMs: pollMs });

    // public key ไม่ใช่ความลับ: เก็บค่าล่าสุดไว้แสดงได้แม้ตอนนี้เครื่องไม่พร้อม
    let lastKey = null;
    async function readKey() {
        try {
            const pub = await agent.publicKey();
            lastKey = {
                line: authorizedKeyLine(pub, agent.comment),
                fingerprint: fingerprint(ed25519Blob(pub)),
                fetchedAt: new Date().toISOString(),
            };
            return { ...lastKey, fromCache: false };
        } catch (err) {
            if (lastKey) return { ...lastKey, fromCache: true, error: err.message };
            throw Object.assign(new Error(`อ่าน key จากเครื่องไม่ได้: ${err.message}`), { status: 503 });
        }
    }

    const routes = {
        // เปิด/ปิด socket ของ agent (ไม่เกี่ยวกับการอนุมัติ: การเซ็นยังต้องกดบนเครื่องเสมอ)
        'POST /api/agent/start': async () => {
            try {
                return await agent.start();
            } catch (err) {
                throw Object.assign(new Error(err.message), { status: 409 });
            }
        },
        'POST /api/agent/stop': async () => agent.stop(),
        'GET /api/history': async ({ url }) => {
            const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 100, 1), 1000);
            return { file: history.file, entries: history.recent(limit) };
        },
        'GET /api/key': readKey,
        // สร้างคำสั่งให้ผู้ใช้ copy ไปรันเอง: backend ไม่เชื่อมต่อ server และไม่รันคำสั่งนี้
        'POST /api/add-key-command': async ({ body }) => {
            const key = await readKey();
            return {
                ...buildAddKeyCommands({ user: body.user, host: body.host, port: body.port ?? 22,
                    keyLine: key.line, socketPath: agent.socketPath }),
                keyFingerprint: key.fingerprint,
            };
        },
    };
    const dashboard = createDashboard({ agent, monitor, port, routes });
    const { url, port: actualPort } = await dashboard.listen();

    agent.on('sign-end', (e) => {
        try {
            const entry = history.append({ time: e.time, ...e.request, keyFingerprint: e.keyFingerprint,
                result: e.result, error: e.error });
            dashboard.broadcast('history', entry);
        } catch (err) {
            log(`บันทึกประวัติไม่ได้: ${err.message}`);
        }
    });

    monitor.start();
    let agentError = null;
    if (startAgent) {
        try {
            await agent.start();
        } catch (err) {
            agentError = err.message;   // เช่น มี agent อื่นใช้ socket อยู่: dashboard ยังเปิดได้
            log(`เริ่ม agent ไม่ได้: ${err.message}`);
        }
    }

    return {
        url,
        port: actualPort,
        token: dashboard.token,
        agent,
        monitor,
        history,
        agentError,
        async close() {
            monitor.stop();
            await dashboard.close();
            await agent.stop();
            await agent.ledger.close();
        },
    };
}

module.exports = { startBackend };
