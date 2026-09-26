const net = require('net');
const fs = require('fs');

const SOCK = '/tmp/ledger-agent.sock';
if (fs.existsSync(SOCK)) fs.unlinkSync(SOCK);   // ลบ socket เก่าที่ค้าง

const server = net.createServer((conn) => {
    conn.on('data', (buf) => {
        console.log('ได้รับ:', buf.toString('hex'));
    });
});

server.listen(SOCK, () => console.log('agent รออยู่ที่', SOCK));