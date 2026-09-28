const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { authorizedKeyLine, fingerprint, ed25519Blob } = require('../lib/ssh-key');

const TEST_KEY_FILE = path.join(__dirname, '..', 'speculos-test-key.pub');

test('builds the same authorized_keys line as the saved Speculos key', () => {
    const [, b64] = fs.readFileSync(TEST_KEY_FILE, 'utf8').trim().split(' ');
    const pub = Buffer.from(b64, 'base64').subarray(-32);
    assert.strictEqual(authorizedKeyLine(pub), fs.readFileSync(TEST_KEY_FILE, 'utf8').trim());
});

test('fingerprint matches ssh-keygen -l', (t) => {
    let expected;
    try {
        expected = execFileSync('ssh-keygen', ['-lf', TEST_KEY_FILE], { encoding: 'utf8' }).split(' ')[1];
    } catch {
        return t.skip('ssh-keygen not available');
    }
    const [, b64] = fs.readFileSync(TEST_KEY_FILE, 'utf8').trim().split(' ');
    assert.strictEqual(fingerprint(Buffer.from(b64, 'base64')), expected);
});

test('rejects keys that are not 32 bytes', () => {
    assert.throws(() => ed25519Blob(Buffer.alloc(31)), /32 bytes/);
});
