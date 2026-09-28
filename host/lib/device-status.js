// ตรวจสถานะเครื่องเป็นระยะ: เจอเครื่องไหม, ล็อกอยู่ไหม, เปิดแอปของเราอยู่ไหม
// - ทุกการคุยกับเครื่องผ่านคิวของ agent (ห้ามแทรก APDU ระหว่างการเซ็น)
// - ไม่ตรวจระหว่างรอผู้ใช้กดบนเครื่อง: เครื่องจะตอบ 6901 และการรอกดคือสถานะที่รู้อยู่แล้ว
const { EventEmitter } = require('events');

class DeviceMonitor extends EventEmitter {
    constructor({ agent, ledger = agent.ledger, intervalMs = 2000 } = {}) {
        super();
        this.agent = agent;
        this.ledger = ledger;
        this.intervalMs = intervalMs;
        this.timer = null;
        this.polling = false;
        this.status = {
            transport: ledger.TRANSPORT,
            checkedAt: null,
            connected: false,
            locked: false,
            currentApp: null,
            appOpen: false,
            error: null,
        };
    }

    start() {
        if (this.timer) return;
        this.poll();
        this.timer = setInterval(() => this.poll(), this.intervalMs);
    }

    stop() {
        clearInterval(this.timer);
        this.timer = null;
    }

    update(next) {
        const changed = ['connected', 'locked', 'currentApp', 'appOpen', 'error']
            .some((k) => this.status[k] !== next[k]);
        this.status = { ...this.status, ...next, checkedAt: new Date().toISOString() };
        if (changed) this.emit('status', this.status);
    }

    async check() {
        if (!(await this.ledger.deviceConnected())) {
            return { connected: false, locked: false, currentApp: null, appOpen: false, error: null };
        }
        const app = await this.agent.withDevice(() => this.ledger.getAppAndVersion());
        if (app.status === '5515') {
            return { connected: true, locked: true, currentApp: null, appOpen: false, error: null };
        }
        if (app.status !== '9000') {
            return { connected: true, locked: false, currentApp: null, appOpen: false, error: `status ${app.status}` };
        }
        const currentApp = app.name === 'BOLOS' ? null : app.name;   // BOLOS = หน้า dashboard ของเครื่อง
        return {
            connected: true,
            locked: false,
            currentApp,
            appOpen: currentApp === this.ledger.APP_NAME,
            error: null,
        };
    }

    async poll() {
        if (this.polling || this.agent.pending) return;
        this.polling = true;
        try {
            this.update(await this.check());
        } catch (err) {
            this.update({ connected: false, locked: false, currentApp: null, appOpen: false, error: err.message });
        } finally {
            this.polling = false;
        }
    }
}

module.exports = { DeviceMonitor };
