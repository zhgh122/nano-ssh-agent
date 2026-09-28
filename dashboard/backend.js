// ประกอบ agent + ตัวตรวจสถานะเครื่อง + HTTP server เข้าด้วยกัน
// ใช้ทั้งจาก cli.js (เปิดผ่านเบราว์เซอร์) และ electron/main.js
const { LedgerAgent } = require('../host/lib/agent-core');
const { DeviceMonitor } = require('../host/lib/device-status');
const { createDashboard } = require('./server');
const { authorizedKeyLine, fingerprint, ed25519Blob } = require('../host/lib/ssh-key');

async function startBackend({ port = 0, startAgent = true, ledger, socketPath, pollMs = 2000, log = () => {} } = {}) {
    const agent = new LedgerAgent({ ...(ledger && { ledger }), ...(socketPath && { socketPath }) });
    agent.on('log', log);
    const monitor = new DeviceMonitor({ agent, intervalMs: pollMs });

    // public key ไม่ใช่ความลับ: เก็บค่าล่าสุดไว้แสดงได้แม้ตอนนี้เครื่องไม่พร้อม
    let lastKey = null;
    const routes = {
        'GET /api/key': async () => {
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
        },
    };
    const dashboard = createDashboard({ agent, monitor, port, routes });
    const { url, port: actualPort } = await dashboard.listen();

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
