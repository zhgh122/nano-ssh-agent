// ที่อยู่ของ agent: Windows ใช้ named pipe (OpenSSH for Windows), ระบบอื่นใช้ Unix socket
const IS_WINDOWS = process.platform === 'win32';

// ค่าเริ่มต้นไม่ใช้ \\.\pipe\openssh-ssh-agent เพราะชนกับ service "OpenSSH Authentication Agent"
// ของ Windows ตั้ง LEDGER_AGENT_SOCK=\\.\pipe\openssh-ssh-agent ได้ถ้าปิด service นั้นแล้ว
const DEFAULT_SOCKET = IS_WINDOWS ? '\\\\.\\pipe\\nano-ssh-agent' : '/tmp/nano-ssh-agent.sock';

function defaultSocketPath() {
    return process.env.LEDGER_AGENT_SOCK || DEFAULT_SOCKET;
}

function isNamedPipe(p) {
    return p.startsWith('\\\\.\\pipe\\') || p.startsWith('//./pipe/');
}

module.exports = { IS_WINDOWS, DEFAULT_SOCKET, defaultSocketPath, isNamedPipe };
