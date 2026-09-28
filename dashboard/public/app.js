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

function el(tag, text, className) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = text;
    if (className) e.className = className;
    return e;
}

// คำอธิบายคำขอเซ็น (ข้อความล้วน ไม่ใช้ innerHTML)
function describeRequest(r) {
    if (!r) return 'Signature request';
    if (r.kind === 'ssh-login') return `Login as user "${r.user}"`;
    if (r.kind === 'sshsig') return `Sign file/message (namespace "${r.namespace}")`;
    return 'Unknown data (not a login)';
}

function describeServer(server) {
    if (!server) return { main: 'Unknown', sub: 'ssh sent no session-bind (OpenSSH older than 8.9) or its signature did not verify' };
    const main = server.names && server.names.length ? server.names.join(', ')
        : server.hashedMatches ? 'In known_hosts (hashed name)' : 'Not in known_hosts';
    const sub = `${server.fingerprint}${server.forwarded ? ' · via agent forwarding' : ''}`;
    return { main, sub };
}

const RESULT_TEXT = { approved: 'Approved', rejected: 'Rejected', error: 'Error' };

function historyRow(e) {
    const tr = document.createElement('tr');
    const when = el('td', new Date(e.time).toLocaleString(), 'when');
    const what = el('td', describeRequest(e));
    const server = el('td');
    if (e.kind === 'ssh-login') {
        const srv = describeServer(e.server);
        server.append(el('span', srv.main), el('span', srv.sub, 'sub'));
    } else {
        server.textContent = '-';
    }
    const result = el('td');
    result.append(el('span', RESULT_TEXT[e.result] || e.result, `badge ${e.result}`));
    if (e.error) result.append(el('span', e.error, 'sub'));
    tr.append(when, what, server, result);
    return tr;
}

function showHistory(entries, { prepend = false } = {}) {
    const tbody = $('history-rows');
    if (!prepend) tbody.replaceChildren();
    for (const e of prepend ? [...entries].reverse() : entries) {
        if (prepend) tbody.prepend(historyRow(e)); else tbody.append(historyRow(e));
    }
    const any = tbody.children.length > 0;
    $('history-empty').hidden = any;
    $('history-wrap').hidden = !any;
}

async function loadHistory() {
    try {
        const { file, entries } = await api('GET', '/api/history?limit=200');
        $('history-file').textContent = file;
        showHistory(entries);
    } catch (err) {
        $('history-empty').hidden = false;
        $('history-empty').textContent = `Cannot read history: ${err.message}`;
    }
}

function renderState({ agent, device }) {
    setDot('st-agent', agent.running ? 'ok' : 'bad');
    $('st-agent-text').textContent = agent.running ? 'Running' : 'Stopped';
    $('st-socket').textContent = agent.socketPath;
    $('st-transport').textContent = agent.transport === 'usb' ? 'USB (real device)'
        : agent.transport === 'speculos' ? 'Speculos (emulator)' : agent.transport;

    if (!device.connected) {
        setDot('st-device', 'bad');
        $('st-device-text').textContent = 'Not found';
    } else if (device.locked) {
        setDot('st-device', 'warn');
        $('st-device-text').textContent = 'Connected, locked';
    } else {
        setDot('st-device', 'ok');
        $('st-device-text').textContent = 'Connected';
    }

    if (agent.pending) {
        setDot('st-app', 'warn');
        $('st-app-text').textContent = 'Waiting for a button press';
    } else if (device.appOpen) {
        setDot('st-app', 'ok');
        $('st-app-text').textContent = 'Nano SSH Agent is open';
    } else {
        setDot('st-app', device.connected && !device.locked ? 'warn' : '');
        $('st-app-text').textContent = device.currentApp ? `Another app is open (${device.currentApp})`
            : device.connected && !device.locked ? 'Nano SSH Agent is not open' : '-';
    }

    $('agent-start').hidden = agent.running;
    $('agent-stop').hidden = !agent.running;

    $('pending').hidden = !agent.pending;
    $('pending-since').textContent = agent.pending ? `since ${time(agent.pending.since)}` : '';
    if (agent.pending) {
        const req = agent.pending.request;
        const srv = req && req.kind === 'ssh-login' ? describeServer(req.server) : null;
        $('pending-what').textContent = describeRequest(req) + (srv ? ` to ${srv.main}` : '');
    }
    $('st-error').hidden = !device.error;
    $('st-error').textContent = device.error || '';
}

let keyLoading = false;
async function loadKey() {
    if (keyLoading) return;
    keyLoading = true;
    $('key-refresh').disabled = true;
    try {
        const key = await api('GET', '/api/key');
        $('key-empty').hidden = true;
        $('key-body').hidden = false;
        $('key-fp').textContent = key.fingerprint;
        $('key-line').textContent = key.line;
        $('key-cache').hidden = !key.fromCache;
        $('key-cache').textContent = key.fromCache
            ? `Read on ${new Date(key.fetchedAt).toLocaleString()} (the device cannot be read right now)` : '';
        $('key-error').hidden = true;
    } catch (err) {
        $('key-error').hidden = false;
        $('key-error').textContent = err.message;
    } finally {
        keyLoading = false;
        $('key-refresh').disabled = false;
    }
}

async function copyKey() {
    const text = $('key-line').textContent;
    try {
        await navigator.clipboard.writeText(text);
        $('key-copied').textContent = 'Copied';
    } catch {
        // สำรอง: เลือกข้อความไว้ให้กด Ctrl+C เอง
        const range = document.createRange();
        range.selectNodeContents($('key-line'));
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        $('key-copied').textContent = 'Text selected, press Ctrl+C';
    }
    setTimeout(() => { $('key-copied').textContent = ''; }, 3000);
}

// อ่าน key ครั้งแรกเมื่อเครื่องพร้อม (แอปเปิดและไม่มีการรอกด)
let keyLoadedOnce = false;
function maybeLoadKey({ agent, device }) {
    if (!keyLoadedOnce && device.appOpen && !agent.pending) {
        keyLoadedOnce = true;
        loadKey();
    }
}

async function agentAction(action) {
    const buttons = [$('agent-start'), $('agent-stop')];
    buttons.forEach((b) => { b.disabled = true; });
    $('agent-error').hidden = true;
    try {
        await api('POST', `/api/agent/${action}`, {});
    } catch (err) {
        $('agent-error').hidden = false;
        $('agent-error').textContent = action === 'start' ? `Cannot start the agent: ${err.message}` : err.message;
    } finally {
        buttons.forEach((b) => { b.disabled = false; });
    }
}

async function copyFrom(id, button) {
    const text = $(id).textContent;
    const old = button.textContent;
    try {
        await navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
    } catch {
        const range = document.createRange();
        range.selectNodeContents($(id));
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        button.textContent = 'Selected, press Ctrl+C';
    }
    setTimeout(() => { button.textContent = old; }, 2500);
}

async function buildAddKey(event) {
    event.preventDefault();
    $('ak-error').hidden = true;
    try {
        const r = await api('POST', '/api/add-key-command', {
            user: $('ak-user').value.trim(),
            host: $('ak-host').value.trim(),
            port: Number($('ak-port').value || 22),
        });
        $('ak-fp').textContent = `Key to add: ${r.keyFingerprint} → ${r.target}`;
        $('ak-posix').textContent = r.posix;
        $('ak-ps').textContent = r.powershell;
        $('ak-test-posix').textContent = r.testPosix;
        $('ak-test-ps').textContent = r.testPowershell;
        $('ak-result').hidden = false;
    } catch (err) {
        $('ak-result').hidden = true;
        $('ak-error').hidden = false;
        $('ak-error').textContent = err.message;
    }
}

function connectEvents() {
    const es = new EventSource(`/api/events?token=${encodeURIComponent(token)}`);
    es.addEventListener('state', (e) => {
        const st = JSON.parse(e.data);
        renderState(st);
        maybeLoadKey(st);
    });
    es.addEventListener('history', (e) => showHistory([JSON.parse(e.data)], { prepend: true }));
    es.onopen = () => { $('conn').className = 'pill on'; $('conn').textContent = 'real-time'; };
    es.onerror = () => { $('conn').className = 'pill off'; $('conn').textContent = 'Disconnected, retrying...'; };
}

if (!token) {
    $('no-token').hidden = false;
    $('conn').textContent = 'No token';
} else {
    $('key-refresh').addEventListener('click', loadKey);
    $('key-copy').addEventListener('click', copyKey);
    $('agent-start').addEventListener('click', () => agentAction('start'));
    $('addkey-form').addEventListener('submit', buildAddKey);
    for (const b of document.querySelectorAll('button[data-copy]')) {
        b.addEventListener('click', () => copyFrom(b.dataset.copy, b));
    }
    $('agent-stop').addEventListener('click', () => agentAction('stop'));
    loadHistory();
    connectEvents();
}
