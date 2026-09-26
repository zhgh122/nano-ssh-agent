async function main() {
    const sig = await sign([44, 1, 0, 0, 0], Buffer.from('a'.repeat(300)));
    console.log(sig);
}

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

async function getPublicKey(path) {
    const apdu = buildApdu(0x05, 0x00, 0x00, encodePath(path));
    return await exchange(apdu);
}

async function exchange(apduHex) {
    const res = await fetch('http://localhost:5000/apdu', {
        method: 'POST',
        body: JSON.stringify({ data: apduHex }),
    });
    const json = await res.json();
    const reply = json.data;
    const status = reply.slice(-4);
    const data = reply.slice(0, -4);

    if (status !== '9000') {
        throw new Error(`Ledger error: ${status}`);
    }
    return data;
}

async function sign(path, message) {
    // ก้อน 0: path
    await exchange(buildApdu(0x06, 0x00, 0x80, encodePath(path)));

    // ก้อน 1, 2, ...: ข้อความ ทีละไม่เกิน 255 ไบต์
    let chunk = 1;
    let result;
    for (let offset = 0; offset < message.length; offset += 255) {
        const part = message.subarray(offset, offset + 255);
        const isLast = offset + 255 >= message.length;
        const p2 = isLast ? 0x00 : 0x80;
        result = await exchange(buildApdu(0x06, chunk, p2, part));
        chunk++;
    }
    return result;
}

main();