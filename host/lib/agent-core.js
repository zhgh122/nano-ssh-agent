// ssh-agent ที่ใช้ Ledger เป็นที่เก็บ key (ed25519)
// โปรโตคอล: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
//
// ใช้ได้ทั้งจาก CLI (agent.js) และ dashboard: สถานะและเหตุการณ์ส่งออกเป็น event
//   'state'      สถานะเปลี่ยน (เริ่ม/หยุด/เริ่มหรือจบการรอกดบนเครื่อง)
//   'log'        ข้อความสำหรับแสดงผล
// agent นี้ไม่มีทางอนุมัติการเซ็นเอง: ทุกลายเซ็นมาจากเครื่องหลังผู้ใช้กด Approve เท่านั้น
const net = require('net');
const fs = require('fs');
const { EventEmitter } = require('events');
const { sshString, uint32, frame, Reader } = require('./ssh-wire');
const { defaultSocketPath, isNamedPipe, IS_WINDOWS } = require('./sock-path');

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

// ข้อความที่ใหญ่กว่านี้ถือว่าผิดปกติ ตัดการเชื่อมต่อทิ้ง
const MAX_MESSAGE_LEN = 256 * 1024;

const KEY_TYPE = Buffer.from('ssh-ed25519');

class LedgerAgent extends EventEmitter {
    constructor({ ledger = require('../ledger'), socketPath = defaultSocketPath(), comment = 'ledger' } = {}) {
        super();
        this.ledger = ledger;
        this.path = ledger.SSH_PATH;
        this.socketPath = socketPath;
        this.comment = comment;
        this.server = null;
        this.connections = new Set();
        this.pending = null;          // { since } ระหว่างรอผู้ใช้กดบนเครื่อง
        this.deviceQueue = Promise.resolve();
    }

    state() {
        return {
            running: this.server !== null,
            socketPath: this.socketPath,
            transport: this.ledger.TRANSPORT,
            pending: this.pending ? { since: this.pending.since } : null,
        };
    }

    emitState() {
        this.emit('state', this.state());
    }

    log(message) {
        this.emit('log', message);
    }

    // คุยกับเครื่องได้ทีละคำสั่ง ทุกงานที่ใช้เครื่อง (รวมการเช็กสถานะ) ต้องผ่านคิวนี้
    withDevice(fn) {
        const run = this.deviceQueue.then(fn, fn);
        this.deviceQueue = run.catch(() => {});
        return run;
    }

    // ถามเครื่องทุกครั้ง ไม่ cache: เครื่องจริงอาจถูกถอด/เปลี่ยน/ล็อกได้ตลอด
    async publicKey() {
        const pub = Buffer.from(await this.withDevice(() => this.ledger.getPublicKey(this.path)), 'hex');
        if (pub.length !== 32) throw new Error(`unexpected public key length ${pub.length}`);
        return pub;
    }

    static keyBlob(pub) {
        return Buffer.concat([sshString(KEY_TYPE), sshString(pub)]);
    }

    async handleIdentities() {
        const blob = LedgerAgent.keyBlob(await this.publicKey());
        return frame(SSH_AGENT_IDENTITIES_ANSWER,
            Buffer.concat([uint32(1), sshString(blob), sshString(Buffer.from(this.comment))]));
    }

    async handleSign(body) {
        const r = new Reader(body);
        const reqBlob = r.string();
        const data = r.string();
        r.uint32();  // flags ไม่มีผลกับ ed25519
        if (!r.done()) throw new Error('bad sign request');

        if (!reqBlob.equals(LedgerAgent.keyBlob(await this.publicKey()))) throw new Error('unknown key');

        this.log(`ขอลายเซ็น ${data.length} ไบต์ รอกดยืนยันบนเครื่อง...`);
        const sigHex = await this.withDevice(async () => {
            this.pending = { since: new Date().toISOString() };
            this.emitState();
            try {
                return await this.ledger.sign(this.path, data);
            } finally {
                this.pending = null;
                this.emitState();
            }
        });
        const sig = Buffer.from(sigHex, 'hex');
        if (sig.length !== 64) throw new Error(`unexpected signature length ${sig.length}`);
        return frame(SSH_AGENT_SIGN_RESPONSE, sshString(Buffer.concat([sshString(KEY_TYPE), sshString(sig)])));
    }

    async handleMessage(msg) {
        const type = msg[0];
        const body = msg.subarray(1);
        try {
            switch (type) {
                case SSH_AGENTC_REQUEST_IDENTITIES:
                    return await this.handleIdentities();
                case SSH_AGENTC_SIGN_REQUEST:
                    return await this.handleSign(body);
                default:
                    return frame(SSH_AGENT_FAILURE);
            }
        } catch (err) {
            this.log(`คำขอ ${type} ล้มเหลว: ${err.message}`);
            return frame(SSH_AGENT_FAILURE);
        }
    }

    onConnection(conn) {
        this.connections.add(conn);
        conn.on('close', () => this.connections.delete(conn));
        let pending = Buffer.alloc(0);
        // ตอบตามลำดับที่รับเข้ามา แม้ client จะส่งหลายคำขอติดกัน
        let replyChain = Promise.resolve();

        conn.on('data', (chunk) => {
            pending = Buffer.concat([pending, chunk]);
            while (pending.length >= 4) {
                const len = pending.readUInt32BE(0);
                if (len === 0 || len > MAX_MESSAGE_LEN) {
                    this.log(`ข้อความยาวผิดปกติ ตัดการเชื่อมต่อ: ${len}`);
                    conn.destroy();
                    return;
                }
                if (pending.length < 4 + len) break;  // ยังมาไม่ครบ รอก้อนถัดไป
                const msg = pending.subarray(4, 4 + len);
                pending = pending.subarray(4 + len);
                replyChain = replyChain
                    .then(() => this.handleMessage(msg))
                    .then((reply) => { if (!conn.destroyed) conn.write(reply); });
            }
        });
        conn.on('error', (err) => this.log(`socket error: ${err.message}`));
    }

    // มี agent อื่นฟังอยู่ที่ socket นี้ไหม (ต่อได้ = มี)
    static isAlive(socketPath) {
        return new Promise((resolve) => {
            const c = net.connect(socketPath);
            c.once('connect', () => { c.destroy(); resolve(true); });
            c.once('error', () => resolve(false));
        });
    }

    async start() {
        if (this.server) return this.state();
        const unixSocket = !isNamedPipe(this.socketPath);
        if (unixSocket && fs.existsSync(this.socketPath)) {
            if (await LedgerAgent.isAlive(this.socketPath)) {
                throw new Error(`another agent is already listening on ${this.socketPath}`);
            }
            fs.unlinkSync(this.socketPath);  // socket เก่าที่ค้างจาก process ที่ตายไปแล้ว
        }

        const server = net.createServer((conn) => this.onConnection(conn));
        // ให้ socket เป็น 0600 ตั้งแต่สร้าง (named pipe ไม่มี umask)
        const oldUmask = (unixSocket && !IS_WINDOWS) ? process.umask(0o177) : null;
        try {
            await new Promise((resolve, reject) => {
                server.once('error', reject);
                server.listen(this.socketPath, () => { server.off('error', reject); resolve(); });
            });
        } catch (err) {
            if (err.code === 'EADDRINUSE') {
                throw new Error(`another agent is already listening on ${this.socketPath}`);
            }
            throw err;
        } finally {
            if (oldUmask !== null) process.umask(oldUmask);
        }
        server.on('error', (err) => this.log(`agent server error: ${err.message}`));
        this.server = server;
        this.log(`agent รออยู่ที่ ${this.socketPath} (transport: ${this.ledger.TRANSPORT})`);
        this.emitState();
        return this.state();
    }

    async stop() {
        if (!this.server) return this.state();
        const server = this.server;
        this.server = null;
        for (const conn of this.connections) conn.destroy();  // คำขอที่ค้างอยู่จะไม่ได้คำตอบ
        await new Promise((resolve) => server.close(() => resolve()));
        if (!isNamedPipe(this.socketPath) && fs.existsSync(this.socketPath)) fs.unlinkSync(this.socketPath);
        this.log('agent หยุดแล้ว');
        this.emitState();
        return this.state();
    }
}

module.exports = {
    LedgerAgent,
    SSH_AGENT_FAILURE,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENT_SIGN_RESPONSE,
};
