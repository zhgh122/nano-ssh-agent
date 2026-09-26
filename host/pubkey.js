const pubHex = process.argv[2];
const pubKey = Buffer.from(pubHex, 'hex');

function sshString(data) {
    const byteBuffer = Buffer.alloc(4);
    byteBuffer.writeUInt32BE(data.length);
    const mergedBuffer = Buffer.concat([byteBuffer, data]);
    return mergedBuffer;
}

const typeField = sshString(Buffer.from('ssh-ed25519'));
const keyField = sshString(pubKey);

const keyBlob = Buffer.concat([typeField, keyField]);
const keyBase64 = keyBlob.toString('base64');
const sshLine = `ssh-ed25519 ${keyBase64} ledger`;
console.log(sshLine);