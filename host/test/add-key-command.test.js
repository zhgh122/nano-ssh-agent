const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { buildAddKeyCommands, validate } = require('../lib/add-key-command');

const KEY = fs.readFileSync(path.join(__dirname, '..', 'speculos-test-key.pub'), 'utf8').trim();

test('rejects values that could inject commands or ssh options', () => {
    const bad = [
        { user: 'a;id', host: 'h', port: 22 },
        { user: '-oProxyCommand=id', host: 'h', port: 22 },
        { user: 'u', host: '$(id)', port: 22 },
        { user: 'u', host: '-oProxyCommand=id', port: 22 },
        { user: 'u', host: 'h h', port: 22 },
        { user: "u'", host: 'h', port: 22 },
        { user: 'u', host: 'h', port: '22; id' },
        { user: 'u', host: 'h', port: 0 },
        { user: 'u', host: 'h', port: 70000 },
    ];
    for (const b of bad) assert.ok(validate(b).errors.length > 0, JSON.stringify(b));
    for (const good of [
        { user: 'ubuntu', host: '203.0.113.10', port: 2222 },
        { user: 'deploy.user', host: 'server-1.example.com', port: 22 },
        { user: 'root', host: '[2001:db8::1]', port: 22 },
    ]) assert.deepStrictEqual(validate(good).errors, [], JSON.stringify(good));
    assert.throws(() => buildAddKeyCommands({ user: 'u', host: 'h', port: 22, keyLine: 'ssh-ed25519 AAAA ledger; id' }), /ssh-ed25519/);
});

test('commands contain the key and target, port option only when not 22', () => {
    const c = buildAddKeyCommands({ user: 'ubuntu', host: 'srv.example', port: 2222, keyLine: KEY, socketPath: '/tmp/nano-ssh-agent.sock' });
    assert.match(c.posix, /^ssh -p 2222 ubuntu@srv\.example '/);
    assert.ok(c.posix.includes(KEY));
    assert.match(c.powershell, /\| ssh -p 2222 ubuntu@srv\.example "tr -d '\\r' \| sh"$/);
    assert.strictEqual(c.testPosix, "SSH_AUTH_SOCK='/tmp/nano-ssh-agent.sock' ssh -p 2222 ubuntu@srv.example");
    const c22 = buildAddKeyCommands({ user: 'u', host: '2001:db8::1', port: 22, keyLine: KEY });
    assert.match(c22.posix, /^ssh u@\[2001:db8::1\] '/);
});

// รันคำสั่ง POSIX จริงโดยแทน ssh ด้วยสคริปต์ที่รันคำสั่งฝั่ง server ใน HOME ชั่วคราว
function runPosix(command, home, shell) {
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'fakessh-'));
    fs.writeFileSync(path.join(bin, 'ssh'), `#!/bin/sh\nfor last; do :; done\nexec ${shell} -c "$last"\n`, { mode: 0o755 });
    return execFileSync('/bin/sh', ['-c', command], {
        env: { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}` }, encoding: 'utf8',
    });
}

for (const shell of ['sh', 'bash']) {
    test(`generated POSIX command works on the server side (${shell}): add, keep, no duplicate, perms`, () => {
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'home-'));
        const { posix } = buildAddKeyCommands({ user: 'u', host: 'h', port: 22, keyLine: KEY });
        // ไม่มี ~/.ssh เลย
        assert.match(runPosix(posix, home, shell), /key added/);
        const f = path.join(home, '.ssh', 'authorized_keys');
        assert.strictEqual(fs.readFileSync(f, 'utf8'), `${KEY}\n`);
        assert.strictEqual(fs.statSync(path.join(home, '.ssh')).mode & 0o777, 0o700);
        assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
        // รันซ้ำ: ไม่เพิ่มซ้ำ
        assert.match(runPosix(posix, home, shell), /already authorized/);
        assert.strictEqual(fs.readFileSync(f, 'utf8'), `${KEY}\n`);
        // ไฟล์เดิมไม่มี newline ท้ายไฟล์: key เดิมต้องไม่ถูกต่อบรรทัด
        fs.writeFileSync(f, 'ssh-rsa AAAAEXISTING old@pc');
        runPosix(posix, home, shell);
        assert.strictEqual(fs.readFileSync(f, 'utf8'), `ssh-rsa AAAAEXISTING old@pc\n${KEY}\n`);
    });
}
