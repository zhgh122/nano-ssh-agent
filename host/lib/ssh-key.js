// รูปแบบ public key ที่คนเห็น: บรรทัด authorized_keys และ fingerprint แบบ ssh-keygen -l
const crypto = require('crypto');
const { sshString } = require('./ssh-wire');

const ED25519 = 'ssh-ed25519';

function ed25519Blob(pub) {
    if (pub.length !== 32) throw new Error(`ed25519 public key must be 32 bytes, got ${pub.length}`);
    return Buffer.concat([sshString(Buffer.from(ED25519)), sshString(pub)]);
}

// "ssh-ed25519 AAAA... comment"
function authorizedKeyLine(pub, comment = 'ledger') {
    return `${ED25519} ${ed25519Blob(pub).toString('base64')} ${comment}`;
}

// SHA256:<base64 ไม่มี => ของ key blob ใดก็ได้ (ใช้กับ host key ของ server ด้วย)
function fingerprint(blob) {
    return `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

module.exports = { ED25519, ed25519Blob, authorizedKeyLine, fingerprint };
