// หน้าเว็บ dashboard: ไม่มี framework ไม่โหลดอะไรจากภายนอก ใช้ได้ทั้งในเบราว์เซอร์และ Electron
'use strict';

// token มากับ #token=... ครั้งแรก เก็บไว้ใน sessionStorage แล้วลบออกจาก URL
const token = (() => {
    const m = location.hash.match(/token=([A-Za-z0-9_-]+)/);
    if (m) {
        sessionStorage.setItem('token', m[1]);
        history.replaceState(null, '', location.pathname);
        return m[1];
    }
    return sessionStorage.getItem('token');
})();

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
    const res = await fetch(path, {
        method,
        headers: { Authorization: `Bearer ${token}`, ...(body && { 'Content-Type': 'application/json' }) },
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
}

function setDot(id, level) {
    $(id).className = `dot ${level || ''}`;
}

function time(iso) {
    return iso ? new Date(iso).toLocaleTimeString() : '';
}

function renderState({ agent, device }) {
    setDot('st-agent', agent.running ? 'ok' : 'bad');
    $('st-agent-text').textContent = agent.running ? 'ทำงานอยู่' : 'หยุดอยู่';
    $('st-socket').textContent = agent.socketPath;
    $('st-transport').textContent = agent.transport === 'usb' ? 'USB (เครื่องจริง)'
        : agent.transport === 'speculos' ? 'Speculos (ตัวจำลอง)' : agent.transport;

    if (!device.connected) {
        setDot('st-device', 'bad');
        $('st-device-text').textContent = 'ไม่พบเครื่อง';
    } else if (device.locked) {
        setDot('st-device', 'warn');
        $('st-device-text').textContent = 'เจอเครื่อง แต่ล็อกอยู่';
    } else {
        setDot('st-device', 'ok');
        $('st-device-text').textContent = 'เจอเครื่อง';
    }

    if (agent.pending) {
        setDot('st-app', 'warn');
        $('st-app-text').textContent = 'กำลังรอกดบนเครื่อง';
    } else if (device.appOpen) {
        setDot('st-app', 'ok');
        $('st-app-text').textContent = 'Nano SSH Agent เปิดอยู่';
    } else {
        setDot('st-app', device.connected && !device.locked ? 'warn' : '');
        $('st-app-text').textContent = device.currentApp ? `เปิดแอปอื่นอยู่ (${device.currentApp})`
            : device.connected && !device.locked ? 'ยังไม่ได้เปิดแอป Nano SSH Agent' : '-';
    }

    $('pending').hidden = !agent.pending;
    $('pending-since').textContent = agent.pending ? `ตั้งแต่ ${time(agent.pending.since)}` : '';
    $('st-error').hidden = !device.error;
    $('st-error').textContent = device.error || '';
}

function connectEvents() {
    const es = new EventSource(`/api/events?token=${encodeURIComponent(token)}`);
    es.addEventListener('state', (e) => renderState(JSON.parse(e.data)));
    es.onopen = () => { $('conn').className = 'pill on'; $('conn').textContent = 'real-time'; };
    es.onerror = () => { $('conn').className = 'pill off'; $('conn').textContent = 'ขาดการเชื่อมต่อ กำลังลองใหม่...'; };
}

if (!token) {
    $('no-token').hidden = false;
    $('conn').textContent = 'ไม่มี token';
} else {
    connectEvents();
}
