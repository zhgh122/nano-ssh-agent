// ทดสอบคำสั่ง APDU ของแอปกับ Speculos (ใช้ seed ทดสอบเท่านั้น)
// รัน: node test-apdu.js   (ต้องเปิด Speculos ไว้ที่ SPECULOS_URL)
const crypto = require('crypto');
const { encodePath, buildApdu, getPublicKey, sign } = require('./ledger');

const SPECULOS_URL = process.env.SPECULOS_URL || 'http://localhost:5000';
const PATH = [44, 1, 0, 0, 0];
const INS_SIGN_SSH = 0x10;

let failures = 0;
function check(name, cond, detail = '') {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
    if (!cond) failures++;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ส่ง APDU ดิบ คืน status word (hex 4 ตัว) และข้อมูล
async function raw(apduHex) {
    const res = await fetch(`${SPECULOS_URL}/apdu`, {
        method: 'POST',
        body: JSON.stringify({ data: apduHex }),
    });
    const reply = (await res.json()).data;
    return { sw: reply.slice(-4), data: reply.slice(0, -4) };
}

async function screenText() {
    const res = await fetch(`${SPECULOS_URL}/events?currentscreenonly=true`);
    return (await res.json()).events.map((e) => e.text).join(' | ');
}

async function press(button) {
    await fetch(`${SPECULOS_URL}/button/${button}`, {
        method: 'POST',
        body: JSON.stringify({ action: 'press-and-release' }),
    });
    await sleep(200);
}

async function waitForScreen(text, timeoutMs = 5000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
        if ((await screenText()).includes(text)) return true;
        await sleep(100);
    }
    return false;
}

// เลื่อนไปหน้า Approve/Reject แล้วกดทั้งสองปุ่ม
async function answerPrompt(choice) {
    if (!(await waitForScreen('Sign SSH login?'))) throw new Error('prompt not shown');
    for (let i = 0; i < 5; i++) {
        if ((await screenText()) === choice) {
            await press('both');
            return;
        }
        await press('right');
    }
    throw new Error(`"${choice}" not found`);
}

function verify(pubHex, message, sigHex) {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pubHex, 'hex')]);
    const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return crypto.verify(null, message, key, Buffer.from(sigHex, 'hex'));
}

async function main() {
    const path = encodePath(PATH);

    // --- คำสั่งพื้นฐาน ---
    let r = await raw(buildApdu(0x03, 0, 0, Buffer.alloc(0)));
    check('GET_VERSION', r.sw === '9000' && r.data === '000100', r.data);
    r = await raw(buildApdu(0x04, 0, 0, Buffer.alloc(0)));
    check('GET_APP_NAME', r.sw === '9000' && Buffer.from(r.data, 'hex').toString() === 'Ledger SSH');

    const pub = await getPublicKey(PATH);
    check('GET_PUBLIC_KEY 32 bytes', pub.length === 64, pub);

    // --- คำสั่งเก่าจาก boilerplate ต้องไม่มีแล้ว ---
    for (const ins of [0x06, 0x07, 0x08, 0x22]) {
        r = await raw(buildApdu(ins, 0, 0x80, path));
        check(`INS 0x${ins.toString(16)} removed`, r.sw === '6d00', r.sw);
    }
    r = await raw(buildApdu(0x05, 1, 0, path));
    check('GET_PUBLIC_KEY P1=1 rejected', r.sw === '6a86', r.sw);
    r = await raw(buildApdu(0x05, 0, 0, Buffer.concat([path, Buffer.from([0])])));
    check('GET_PUBLIC_KEY trailing byte rejected', r.sw === '6a87', r.sw);
    r = await raw('e1030000');
    check('wrong CLA rejected', r.sw === '6e00', r.sw);

    // --- เซ็น: ลำดับก้อนผิด / ขนาดเกิน ---
    r = await raw(buildApdu(0x05, 0, 0, path));  // ล้าง context
    r = await raw(buildApdu(INS_SIGN_SSH, 1, 0x00, Buffer.from('x')));
    check('SIGN_SSH data before path rejected', r.sw === '6985', r.sw);
    r = await raw(buildApdu(INS_SIGN_SSH, 0, 0x00, path));
    check('SIGN_SSH chunk 0 with P2_LAST rejected', r.sw === '6a86', r.sw);
    r = await raw(buildApdu(INS_SIGN_SSH, 4, 0x00, Buffer.from('x')));
    check('SIGN_SSH P1 > max rejected', r.sw === '6a86', r.sw);

    await raw(buildApdu(INS_SIGN_SSH, 0, 0x80, path));
    await raw(buildApdu(INS_SIGN_SSH, 1, 0x80, Buffer.alloc(255, 1)));
    await raw(buildApdu(INS_SIGN_SSH, 2, 0x80, Buffer.alloc(255, 2)));
    r = await raw(buildApdu(INS_SIGN_SSH, 3, 0x00, Buffer.alloc(1, 3)));
    check('SIGN_SSH message > 510 bytes rejected', r.sw === '6a87', r.sw);
    check('no prompt after oversize', !(await screenText()).includes('Sign SSH'));

    // --- เซ็นสำเร็จ (ข้อความ 300 ไบต์ = 2 ก้อน) ---
    const msg = crypto.randomBytes(300);
    let pending = sign(PATH, msg);
    await answerPrompt('Approve');
    const sig = await pending;
    check('SIGN_SSH approve returns 64-byte sig', sig.length === 128);
    check('signature verifies with public key', verify(pub, msg, sig));
    check('back to home after approve', await waitForScreen('app is ready'));

    // --- ผู้ใช้ปฏิเสธ ---
    pending = sign(PATH, Buffer.from('reject me')).catch((e) => e);
    await answerPrompt('Reject');
    let err = await pending;
    check('SIGN_SSH reject returns 6985', err instanceof Error && err.message.includes('6985'),
        String(err && err.message));
    check('back to home after reject', await waitForScreen('app is ready'));

    // หลังปฏิเสธ context ถูกล้าง ส่งข้อมูลต่อโดยไม่มี path ต้องไม่ผ่าน
    r = await raw(buildApdu(INS_SIGN_SSH, 1, 0x00, Buffer.from('x')));
    check('context cleared after reject', r.sw === '6985', r.sw);


    console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
    process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
