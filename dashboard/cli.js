// เปิด dashboard แบบเว็บ: node dashboard/cli.js [--port 7373] [--no-agent]
// แล้วเปิด URL ที่พิมพ์ออกมา (มี token อยู่หลัง #) ในเบราว์เซอร์ หรือผ่าน port forward ของ VS Code
const { startBackend } = require('./backend');

const args = process.argv.slice(2);
const portArg = args.indexOf('--port');
const port = portArg >= 0 ? Number(args[portArg + 1]) : Number(process.env.DASHBOARD_PORT || 7373);

startBackend({ port, startAgent: !args.includes('--no-agent'), log: (m) => console.log(m) })
    .then((backend) => {
        console.log(`dashboard: ${backend.url}`);
        console.log('Open this whole link (including #token). Do not share it.');
        const shutdown = async () => { await backend.close(); process.exit(0); };
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
    })
    .catch((err) => {
        console.error(`Cannot start the dashboard: ${err.message}`);
        process.exit(1);
    });
