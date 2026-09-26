// LEDGER_TRANSPORT=speculos (ค่าเริ่มต้น) คุยกับ Speculos ผ่าน REST
// LEDGER_TRANSPORT=usb คุยกับเครื่องจริงผ่าน USB HID
const TRANSPORT = process.env.LEDGER_TRANSPORT || 'speculos';
const SPECULOS_URL = process.env.SPECULOS_URL || 'http://localhost:5000';
// เวลารอหาเครื่องทาง USB (ms) ถ้าไม่มีเครื่องเสียบอยู่จะได้ตอบ failure แทนการค้าง
const USB_OPEN_TIMEOUT_MS = Number(process.env.LEDGER_USB_TIMEOUT_MS || 5000);

// path เฉพาะของแอป: m/44'/1280529224'/0'/0'/0' (0x4C535348 = "LSSH") ทุกระดับ hardened
// ต้องตรงกับ PATH_APP_LOAD_PARAMS ใน Makefile
const SSH_PATH = [44, 0x4c535348, 0, 0, 0];

const INS_GET_PUBLIC_KEY = 0x05;
const INS_SIGN_SSH = 0x10;
const CHUNK_SIZE = 255;

function encodePath(path) {
    const buf = Buffer.alloc(1 + path.length * 4);
    buf.writeUInt8(path.length, 0);
    path.forEach((n, i) => {
        const hardened = (0x80000000 | n) >>> 0;
        buf.writeUInt32BE(hardened, 1 + i * 4);
    });
    return buf;
}

function buildApdu(ins, p1, p2, data) {
    const header = Buffer.from([0xe0, ins, p1, p2, data.length]);
    return Buffer.concat([header, data]).toString('hex');
}

// คำอธิบาย status word ที่เจอบ่อยกับเครื่องจริง
const STATUS_HINTS = {
    '5515': 'device is locked, unlock it',
    '6511': 'Nano SSH Agent app is not open',
    '6e01': 'Nano SSH Agent app is not open',
    '6d02': 'Nano SSH Agent app is not open',
    '6985': 'rejected on device',
    '6901': 'device is busy with another request',
};

async function speculosExchange(apduHex) {
    const res = await fetch(`${SPECULOS_URL}/apdu`, {
        method: 'POST',
        body: JSON.stringify({ data: apduHex }),
    });
    const json = await res.json();
    return json.data;
}

let hidTransport = null;

async function usbExchange(apduHex) {
    if (!hidTransport) {
        // โหลดเฉพาะตอนใช้ USB จะได้ไม่ต้องมี native module ตอนทดสอบกับ Speculos
        const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
        hidTransport = await TransportNodeHid.create(USB_OPEN_TIMEOUT_MS, USB_OPEN_TIMEOUT_MS);
        hidTransport.on('disconnect', () => { hidTransport = null; });
    }
    try {
        // ไม่ตั้ง abortTimeoutMs: รอจนกว่าผู้ใช้จะกดยืนยันหรือปฏิเสธบนเครื่อง
        const reply = await hidTransport.exchange(Buffer.from(apduHex, 'hex'));
        return reply.toString('hex');
    } catch (err) {
        await close();  // เปิดใหม่ในคำขอถัดไป (เช่น ถอดสายแล้วเสียบใหม่)
        throw err;
    }
}

async function exchange(apduHex) {
    let reply;
    if (TRANSPORT === 'usb') {
        reply = await usbExchange(apduHex);
    } else if (TRANSPORT === 'speculos') {
        reply = await speculosExchange(apduHex);
    } else {
        throw new Error(`unknown LEDGER_TRANSPORT "${TRANSPORT}" (use speculos or usb)`);
    }
    const status = reply.slice(-4);
    const data = reply.slice(0, -4);

    if (status !== '9000') {
        const hint = STATUS_HINTS[status];
        throw new Error(`Ledger error: ${status}${hint ? ` (${hint})` : ''}`);
    }
    return data;
}

// ปิดการเชื่อมต่อ USB (ถ้ามี) ให้ process จบได้
async function close() {
    const t = hidTransport;
    hidTransport = null;
    if (t) await t.close().catch(() => {});
}

// คืน public key ed25519 32 ไบต์ เป็น hex
async function getPublicKey(path) {
    const apdu = buildApdu(INS_GET_PUBLIC_KEY, 0x00, 0x00, encodePath(path));
    return await exchange(apdu);
}

// คืนลายเซ็น ed25519 64 ไบต์ เป็น hex (ต้องกดยืนยันบนเครื่อง)
async function sign(path, message) {
    if (message.length === 0) {
        throw new Error('empty message');
    }

    // ก้อน 0: path
    await exchange(buildApdu(INS_SIGN_SSH, 0x00, 0x80, encodePath(path)));

    // ก้อน 1, 2, ...: ข้อความ ทีละไม่เกิน 255 ไบต์
    let chunk = 1;
    let result;
    for (let offset = 0; offset < message.length; offset += CHUNK_SIZE) {
        const part = message.subarray(offset, offset + CHUNK_SIZE);
        const isLast = offset + CHUNK_SIZE >= message.length;
        const p2 = isLast ? 0x00 : 0x80;
        result = await exchange(buildApdu(INS_SIGN_SSH, chunk, p2, part));
        chunk++;
    }
    return result;
}

module.exports = { TRANSPORT, SSH_PATH, encodePath, buildApdu, exchange, getPublicKey, sign, close };

// ทดสอบด้วยมือ: node ledger.js  (LEDGER_TRANSPORT=usb node ledger.js สำหรับเครื่องจริง)
if (require.main === module) {
    (async () => {
        const path = SSH_PATH;
        console.log(`transport: ${TRANSPORT}`);
        console.log('public key:', await getPublicKey(path));
        console.log('signature :', await sign(path, Buffer.from('a'.repeat(300))));
    })()
        .catch((err) => { console.error(err.message); process.exitCode = 1; })
        .finally(close);
}
