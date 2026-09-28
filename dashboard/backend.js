// ประกอบ agent + ตัวตรวจสถานะเครื่อง + HTTP server เข้าด้วยกัน
// ใช้ทั้งจาก cli.js (เปิดผ่านเบราว์เซอร์) และ electron/main.js
const { LedgerAgent } = require('../host/lib/agent-core');
const { DeviceMonitor } = require('../host/lib/device-status');
const { createDashboard } = require('./server');

async function startBackend({ port = 0, startAgent = true, ledger, socketPath, pollMs = 2000, log = () => {} } = {}) {
    const agent = new LedgerAgent({ ...(ledger && { ledger }), ...(socketPath && { socketPath }) });
    agent.on('log', log);
    const monitor = new DeviceMonitor({ agent, intervalMs: pollMs });

    const routes = {};
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
