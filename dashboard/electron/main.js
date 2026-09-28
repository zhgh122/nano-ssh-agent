// ตัวห่อ Electron: รัน backend เดียวกับเวอร์ชันเว็บในโปรเซสหลัก แล้วเปิดหน้าเว็บเดิมในหน้าต่าง
//
// ความปลอดภัย:
// - contextIsolation: true, nodeIntegration: false, sandbox: true, ไม่มี preload
// - โหลดได้เฉพาะ http://127.0.0.1:<port> ของ backend เอง: request อื่นทั้งหมดถูกยกเลิก
// - ห้ามเปลี่ยนหน้าไปที่อื่น ห้ามเปิดหน้าต่างใหม่ ห้ามแนบ <webview>
// - ปฏิเสธ permission ทุกชนิด ยกเว้นการเขียน clipboard (ปุ่ม Copy)
// แอปไม่มีทางอนุมัติการเซ็นเอง: การอนุมัติเกิดบนเครื่อง Ledger เท่านั้น
const { app, BrowserWindow, session } = require('electron');

// แอปที่ติดตั้งใช้กับเครื่องจริงทาง USB (ตั้ง LEDGER_TRANSPORT=speculos เพื่อทดสอบกับตัวจำลอง)
if (!process.env.LEDGER_TRANSPORT) process.env.LEDGER_TRANSPORT = 'usb';

const { startBackend } = require('../backend');

let backend = null;
let win = null;

function lockDown(origin) {
    const ses = session.defaultSession;
    ses.webRequest.onBeforeRequest((details, callback) => {
        const allowed = details.url.startsWith(`${origin}/`) || details.url.startsWith('devtools://');
        callback({ cancel: !allowed });
    });
    ses.setPermissionRequestHandler((_wc, permission, callback) => callback(permission === 'clipboard-sanitized-write'));
    ses.setPermissionCheckHandler((_wc, permission) => permission === 'clipboard-sanitized-write');

    app.on('web-contents-created', (_e, contents) => {
        contents.on('will-navigate', (event, url) => {
            if (!url.startsWith(`${origin}/`)) event.preventDefault();
        });
        contents.on('will-redirect', (event, url) => {
            if (!url.startsWith(`${origin}/`)) event.preventDefault();
        });
        contents.on('will-attach-webview', (event) => event.preventDefault());
        contents.setWindowOpenHandler(() => ({ action: 'deny' }));
    });
}

async function createWindow() {
    backend = await startBackend({ port: 0, log: (m) => console.log(m) });
    const origin = new URL(backend.url).origin;
    lockDown(origin);

    win = new BrowserWindow({
        width: 980,
        height: 860,
        minWidth: 480,
        title: 'Nano SSH Agent',
        autoHideMenuBar: true,
        webPreferences: {
            contextIsolation: true,
            nodeIntegration: false,
            nodeIntegrationInWorker: false,
            sandbox: true,
            webSecurity: true,
            allowRunningInsecureContent: false,
            spellcheck: false,
        },
    });
    await win.loadURL(backend.url);
    win.on('closed', () => { win = null; });
}

if (!app.requestSingleInstanceLock()) {
    app.quit();                        // เปิดซ้ำ: ใช้หน้าต่างเดิม (มี agent ได้ตัวเดียวต่อ socket)
} else {
    app.on('second-instance', () => {
        if (win) {
            if (win.isMinimized()) win.restore();
            win.focus();
        }
    });
    app.whenReady().then(createWindow).catch((err) => {
        console.error(`เปิด dashboard ไม่ได้: ${err.message}`);
        app.exit(1);
    });
    // สั่งปิดจาก terminal/ระบบ: ปิดแบบเรียบร้อย (หยุด agent และลบ socket)
    for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => app.quit());
    // ปิดหน้าต่าง = ปิด agent ด้วย (ทุกระบบ รวม macOS)
    app.on('window-all-closed', () => app.quit());
    let closing = false;
    app.on('before-quit', (event) => {
        if (closing || !backend) return;
        event.preventDefault();
        closing = true;
        backend.close().finally(() => app.exit(0));
    });
}
