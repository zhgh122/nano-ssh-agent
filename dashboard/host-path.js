// หาโฟลเดอร์ host/: ใน repo อยู่ที่ ../host, ในแอป Electron ที่แพ็กแล้วถูกคัดลอกมาไว้ที่ ./host
const fs = require('fs');
const path = require('path');

const HOST_DIR = fs.existsSync(path.join(__dirname, 'host', 'ledger.js'))
    ? path.join(__dirname, 'host')
    : path.join(__dirname, '..', 'host');

function requireHost(rel) {
    return require(path.join(HOST_DIR, rel));
}

module.exports = { HOST_DIR, requireHost };
