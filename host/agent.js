// ssh-agent แบบ command line: ใช้ agent-core และพิมพ์ log ออกหน้าจอ
const { LedgerAgent } = require('./lib/agent-core');
const { IS_WINDOWS } = require('./lib/sock-path');

const agent = new LedgerAgent();
agent.on('log', (message) => console.log(message));

agent.start()
    .then(({ socketPath }) => {
        console.log(IS_WINDOWS
            ? `ใช้งาน (PowerShell): $env:SSH_AUTH_SOCK = "${socketPath}"`
            : `ใช้งาน: export SSH_AUTH_SOCK=${socketPath}`);
    })
    .catch((err) => {
        console.error(`เริ่ม agent ไม่ได้: ${err.message}`);
        process.exit(1);
    });

async function shutdown() {
    await agent.stop();
    await agent.ledger.close();
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
