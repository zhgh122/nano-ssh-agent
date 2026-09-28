// การเข้ารหัส/ถอดรหัสข้อมูลแบบ SSH wire format (RFC 4251 §5)

function sshString(data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    return Buffer.concat([len, data]);
}

function uint32(n) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
}

// ข้อความของ ssh-agent: uint32 ความยาว || byte ชนิด || เนื้อหา
function frame(type, payload = Buffer.alloc(0)) {
    return sshString(Buffer.concat([Buffer.from([type]), payload]));
}

// อ่านข้อมูลทีละช่องจาก buffer และโยน error ทันทีถ้าข้อมูลขาด
class Reader {
    constructor(buf) {
        this.buf = buf;
        this.offset = 0;
    }

    ensure(n) {
        if (this.offset + n > this.buf.length) throw new Error('truncated message');
    }

    byte() {
        this.ensure(1);
        return this.buf[this.offset++];
    }

    bool() {
        return this.byte() !== 0;
    }

    uint32() {
        this.ensure(4);
        const v = this.buf.readUInt32BE(this.offset);
        this.offset += 4;
        return v;
    }

    string() {
        const len = this.uint32();
        this.ensure(len);
        const v = this.buf.subarray(this.offset, this.offset + len);
        this.offset += len;
        return v;
    }

    text() {
        return this.string().toString('utf8');
    }

    done() {
        return this.offset === this.buf.length;
    }

    remaining() {
        return this.buf.length - this.offset;
    }
}

module.exports = { sshString, uint32, frame, Reader };
