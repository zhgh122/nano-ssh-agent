const crypto = require('crypto');

const pubKey    = Buffer.from(process.argv[2], 'hex');
const message   = Buffer.from(process.argv[3]);
const signature = Buffer.from(process.argv[4], 'hex');

const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');

const keyObject = crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, pubKey]),
    format: 'der',
    type: 'spki',
});

const ok = crypto.verify(null, message, keyObject, signature);
console.log(ok);