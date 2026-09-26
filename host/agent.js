// ssh-agent ที่ใช้ Ledger เป็นที่เก็บ key (ed25519)
// โปรโตคอล: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
const net = require('net');
const fs = require('fs');
const { getPublicKey, sign } = require('./ledger');

const SOCK = process.env.LEDGER_AGENT_SOCK || '/tmp/ledger-agent.sock';
const PATH = [44, 1, 0, 0, 0];
const COMMENT = 'ledger';

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

// ข้อความที่ใหญ่กว่านี้ถือว่าผิดปกติ ตัดการเชื่อมต่อทิ้ง
const MAX_MESSAGE_LEN = 256 * 1024;

function sshString(data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    return Buffer.concat([len, data]);
}

function frame(type, payload = Buffer.alloc(0)) {
    return sshString(Buffer.concat([Buffer.from([type]), payload]));
}

// อ่าน string แบบ SSH จาก buf ที่ offset คืน [ข้อมูล, offset ถัดไป]
function readString(buf, offset) {
    if (offset + 4 > buf.length) throw new Error('truncated length');
    const len = buf.readUInt32BE(offset);
    const start = offset + 4;
    if (start + len > buf.length) throw new Error('truncated string');
    return [buf.subarray(start, start + len), start + len];
}

// คุยกับเครื่องได้ทีละคำสั่ง เลยต่อคิวทุกคำขอไว้
let deviceQueue = Promise.resolve();
function withDevice(fn) {
    const run = deviceQueue.then(fn, fn);
    deviceQueue = run.catch(() => {});
    return run;
}

let cachedKeyBlob = null;
async function keyBlob() {
    if (!cachedKeyBlob) {
        const pub = Buffer.from(await withDevice(() => getPublicKey(PATH)), 'hex');
        if (pub.length !== 32) throw new Error(`unexpected public key length ${pub.length}`);
        cachedKeyBlob = Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(pub)]);
    }
    return cachedKeyBlob;
}

async function handleIdentities() {
    const blob = await keyBlob();
    const count = Buffer.alloc(4);
    count.writeUInt32BE(1);
    return frame(SSH_AGENT_IDENTITIES_ANSWER,
        Buffer.concat([count, sshString(blob), sshString(Buffer.from(COMMENT))]));
}

async function handleSign(body) {
    let offset = 0;
    let reqBlob, data;
    [reqBlob, offset] = readString(body, offset);
    [data, offset] = readString(body, offset);
    if (offset + 4 !== body.length) throw new Error('bad sign request');
    // flags ไม่มีผลกับ ed25519 จึงไม่ต้องใช้

    if (!reqBlob.equals(await keyBlob())) throw new Error('unknown key');

    console.log(`ขอลายเซ็น ${data.length} ไบต์ รอกดยืนยันบนเครื่อง...`);
    const sig = Buffer.from(await withDevice(() => sign(PATH, data)), 'hex');
    if (sig.length !== 64) throw new Error(`unexpected signature length ${sig.length}`);

    const signature = Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(sig)]);
    return frame(SSH_AGENT_SIGN_RESPONSE, sshString(signature));
}

async function handleMessage(msg) {
    const type = msg[0];
    const body = msg.subarray(1);
    try {
        switch (type) {
            case SSH_AGENTC_REQUEST_IDENTITIES:
                return await handleIdentities();
            case SSH_AGENTC_SIGN_REQUEST:
                return await handleSign(body);
            default:
                return frame(SSH_AGENT_FAILURE);
        }
    } catch (err) {
        console.error(`คำขอ ${type} ล้มเหลว:`, err.message);
        return frame(SSH_AGENT_FAILURE);
    }
}

function onConnection(conn) {
    let pending = Buffer.alloc(0);
    // ตอบตามลำดับที่รับเข้ามา แม้ client จะส่งหลายคำขอติดกัน
    let replyChain = Promise.resolve();

    conn.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 4) {
            const len = pending.readUInt32BE(0);
            if (len === 0 || len > MAX_MESSAGE_LEN) {
                console.error('ข้อความยาวผิดปกติ ตัดการเชื่อมต่อ:', len);
                conn.destroy();
                return;
            }
            if (pending.length < 4 + len) break;  // ยังมาไม่ครบ รอก้อนถัดไป
            const msg = pending.subarray(4, 4 + len);
            pending = pending.subarray(4 + len);
            replyChain = replyChain
                .then(() => handleMessage(msg))
                .then((reply) => { if (!conn.destroyed) conn.write(reply); });
        }
    });
    conn.on('error', (err) => console.error('socket error:', err.message));
}

if (fs.existsSync(SOCK)) fs.unlinkSync(SOCK);   // ลบ socket เก่าที่ค้าง
const server = net.createServer(onConnection);
const oldUmask = process.umask(0o177);          // ให้ socket เป็น 0600 ตั้งแต่สร้าง
server.listen(SOCK, () => {
    process.umask(oldUmask);
    console.log('agent รออยู่ที่', SOCK);
    console.log(`ใช้งาน: export SSH_AUTH_SOCK=${SOCK}`);
});
