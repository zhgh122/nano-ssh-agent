// ssh-agent แบบ command line: ใช้ agent-core และพิมพ์ log ออกหน้าจอ
const { LedgerAgent } = require('./lib/agent-core');
const { IS_WINDOWS } = require('./lib/sock-path');
const { History } = require('./lib/history');

const agent = new LedgerAgent();
const history = new History();
agent.on('log', (message) => console.log(message));
agent.on('sign-end', (e) => {
    history.append({ time: e.time, ...e.request, keyFingerprint: e.keyFingerprint, result: e.result, error: e.error });
});

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
