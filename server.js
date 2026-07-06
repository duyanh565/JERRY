'use strict';

// ============================================================
//  Jerry Mod TOOL Pro — Standalone API Server
//  Chạy: node server.js
//  DB:   SQLite (tự tạo file jerry.db cùng thư mục)
// ============================================================

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const path       = require('path');
const { DatabaseSync } = require('node:sqlite');
const { randomInt }    = require('crypto');

// ── Config ──────────────────────────────────────────────────
const PORT          = process.env.PORT || 3000;
const ACCESS_SECRET  = process.env.SESSION_SECRET  || 'jerry-mod-access-2024';
const REFRESH_SECRET = process.env.REFRESH_SECRET  || 'jerry-mod-refresh-2024-r9x';
const PUBLIC_DIR    = path.join(__dirname, 'public');

// ── SQLite setup ─────────────────────────────────────────────
const db = new DatabaseSync(path.join(__dirname, 'jerry.db'));
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL DEFAULT 'FREE',
    active INTEGER NOT NULL DEFAULT 1,
    expiry INTEGER NOT NULL DEFAULT 0,
    max_devices INTEGER NOT NULL DEFAULT 1,
    max_uses INTEGER NOT NULL DEFAULT 0,
    uses INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    tool_type TEXT NOT NULL DEFAULT 'Make Data',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    key_val TEXT,
    key_id INTEGER,
    success INTEGER NOT NULL DEFAULT 1,
    ip TEXT,
    message TEXT,
    ts TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    admin_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── JWT helpers ──────────────────────────────────────────────
function signAccess(adminId, username) {
  return jwt.sign({ adminId, username }, ACCESS_SECRET, { expiresIn: '15m' });
}
function signRefresh(adminId) {
  return jwt.sign({ adminId }, REFRESH_SECRET, { expiresIn: '30d' });
}
function verifyAccess(token) {
  try { return jwt.verify(token, ACCESS_SECRET); } catch { return null; }
}
function verifyRefresh(token) {
  try { return jwt.verify(token, REFRESH_SECRET); } catch { return null; }
}

// ── Auth middleware ──────────────────────────────────────────
function requireAdmin(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const p = verifyAccess(h.slice(7));
  if (!p) return res.status(401).json({ error: 'Token hết hạn hoặc không hợp lệ' });
  req.admin = p;
  next();
}

// ── Helpers ──────────────────────────────────────────────────
function getIp(req) {
  const f = req.headers['x-forwarded-for'];
  if (f) return (Array.isArray(f) ? f[0] : f.split(',')[0]).trim();
  return req.socket?.remoteAddress ?? 'unknown';
}
function fingerprint(req) {
  const raw = (req.headers['user-agent'] ?? '') + '|' + getIp(req) + '|' + (req.headers['accept-language'] ?? '');
  let h = 0;
  for (let i = 0; i < raw.length; i++) { h = (h << 5) - h + raw.charCodeAt(i); h |= 0; }
  return Math.abs(h).toString(16).padStart(8, '0') + '-' + raw.length.toString(16);
}
function randStr(len) {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array.from({ length: len }, () => c[randomInt(c.length)]).join('');
}
function addLog(action, opts = {}) {
  db.prepare('INSERT INTO logs (action, key_val, key_id, success, ip, message) VALUES (?,?,?,?,?,?)')
    .run(action, opts.keyVal ?? null, opts.keyId ?? null, opts.success ?? 1, opts.ip ?? null, opts.message ?? null);
}

// ── PATCH DATA (bí mật server-side) ─────────────────────────
const AIM_BODY_BONES = [
  'bone_Hips_Dummy','bone_RightClav','bone_LeftThumb2','bone_RightAnkle','bone_Spine',
  'bone_RightMiddle1','bone_Left_Spine_Backpack','bone_LeftLeg','bone_Hips','bone_LeftMiddle2',
  'bone_RightArm','bone_RightToe','bone_LeftThumb1','bone_LeftAnkle','bone_LeftHand',
  'bone_RightThumb1','bone_LeftF_Hips_Weapon','bone_LeftForeArm','bone_Spine1','bone_RightThumb2',
  'bone_LeftArm','bone_RightForeArm','bone_LeftMiddle1','bone_RightLegUpper','bone_LeftLegUpper',
  'bone_Right_Spine_Weapon','bone_RightIndex1','bone_RightLeg','bone_LeftToe','bone_RightMiddle2',
  'bone_LeftClav','bone_Right_Hips_Weapon','bone_RightHand','bone_Left_Spine_Weapon','bone_LeftIndex1',
  'bone_RightIndex2','bone_LeftIndex2',
];

const HEX_CONFIG = {
  1: [{ find:'4C7B5ABD0A5766BB1E2148BA2AC2CF3B96FB283DE8B117BDE3997F3F0400803F0100803FFCFF7F3F10000000626F6E655F4C6566745F576561706F6E23AAA6B8460ACD70', replace:'170E743FEA5B66BB100448BAC6BFCF3B0DFC283D03B217BDE5997F3F0000604100006041000060410F000000626F6E655F5370696E6531000000000023AAA6B8B2F71FA4' }],
  2: [{ find:'F9B4316974EB4C7B5ABD0A5766BB1E2148BA2AC2CF3B96FB283DE8B117BDE3997F3F0400803F0100803FFCFF7F3F10000000626F6E655F4C6566745F576561706F6E23AAA6B8460ACD706BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000', replace:'F9B4316974EBE10AC0BE55DC98BD69C5D6B300000000AFEC2B40BD3706B7931A5AB7761CC73F761CC73F761CC73F10000000626F6E655F486561640000000000000023AAA6B8B2F71FA46BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000' }],
  3: [{ find:'F9B4316974EB4C7B5ABD0A5766BB1E2148BA2AC2CF3B96FB283DE8B117BDE3997F3F0400803F0100803FFCFF7F3F10000000626F6E655F4C6566745F576561706F6E23AAA6B8460ACD706BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000', replace:'F9B4316974EBD7339CBEBAD7C93CBD3706B600000000AFEC2B40BD3706B7931A5AB7761CC73F761CC73F761CC73F10000000626F6E655F486561640000000000000023AAA6B8B2F71FA46BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000' }],
  4: [
    { find:'4C7B5ABD0A5766BB1E2148BA2AC2CF3B96FB283DE8B117BDE3997F3F0400803F0100803FFCFF7F3F10000000626F6E655F4C6566745F576561706F6E23AAA6B8460ACD70', replace:'7DAE36BD24977FBBB7C8CCB12AC2CF3BEEA34240E8B117BDE3997F3F721CC73F721CC73F721CC73F10000000626F6E655F486561640000000000000023AAA6B8B2F71FA4' },
    { find:'7BD5FEBD6BF1AEBCDA658FB338C2152A1FCD043542A636BE0DE57B3F0100803F0100803F0000803F09000000626F6E655F4E65636BA158C305B2F71FA4', replace:'7BD5FEBD6BF1AEBCDA658FB338C2152A1FCD043542A636BE0DE57B3F0100803F295C8F3F295C8F3F09000000626F6E655F4E65636BA158C305B2F71FA4' },
  ],
  5: [
    { find:'16080EBFCD0B13BD9FC9543F866885BEE6D354BF37B37F3D3E5E0DBF64CD093F2C5603BDDA557FBF7D0E84BD6556653D0000000000000000000000000000803F', replace:'16080EBFCD0B13BD9FC9543F866885BEE6D354BF37B37F3D3E5E0DBF64CD093F2C5603BDDA557FBF7D0E84BD6556653D0000000000000000000000000000FA43' },
    { find:'B4828F3E3AB11A3E02AD723F6BA5E0BEDE28713F12F7153E31909ABEF0DED33ECADB3CBEFB447A3F7F61CFBD11F82D3D0000000000000000000000000000803F', replace:'B4828F3E3AB11A3E02AD723F6BA5E0BEDE28713F12F7153E31909ABEF0DED33ECADB3CBEFB447A3F7F61CFBD11F82D3D0000000000000000000000000000FA43' },
  ],
  6: [
    { find:'F9B4316974EB4C7B5ABD0A5766BB1E2148BA2AC2CF3B96FB283DE8B117BDE3997F3F0400803F0100803FFCFF7F3F10000000626F6E655F4C6566745F576561706F6E23AAA6B8460ACD706BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000', replace:'F9B4316974EBD7339CBEBAD7C93CBD3706B600000000AFEC2B40BD3706B7931A5AB7761CC73F761CC73F761CC73F10000000626F6E655F486561640000000000000023AAA6B8B2F71FA46BF908BE00000000000000008BDD9C30ECCFFFB28BDD1C3DECCF7F3F0000803F0000803F0000803F10000000' },
    { find:'16080EBFCD0B13BD9FC9543F866885BEE6D354BF37B37F3D3E5E0DBF64CD093F2C5603BDDA557FBF7D0E84BD6556653D0000000000000000000000000000803F', replace:'16080EBFCD0B13BD9FC9543F866885BEE6D354BF37B37F3D3E5E0DBF64CD093F2C5603BDDA557FBF7D0E84BD6556653D0000000000000000000000000000FA43' },
    { find:'B4828F3E3AB11A3E02AD723F6BA5E0BEDE28713F12F7153E31909ABEF0DED33ECADB3CBEFB447A3F7F61CFBD11F82D3D0000000000000000000000000000803F', replace:'B4828F3E3AB11A3E02AD723F6BA5E0BEDE28713F12F7153E31909ABEF0DED33ECADB3CBEFB447A3F7F61CFBD11F82D3D0000000000000000000000000000FA43' },
  ],
};

const CACHE_HEX_CONFIG = {
  1: [
    { find:'226e1f3f5300000000000000', replace:'226E1F3F530000000000000000000000000000000000000000000000000000000100000059DFCA3DE48C023E000000001DBB143E' },
    { find:'bf9fb489cd0000000000000000000000', replace:'BF9FB489CD0000000000000000000000000000000000000000000000000000000100000003E11CB3D72830503E00000006D27103E' },
  ],
  3: [
    { find:'a8e7713de48c023e00000000dc5239bd', replace:'64dfca3de48c023e000000009f48623d' },
    { find:'724b723d7283053e00000000180427bd', replace:'3111cb3d7283053e00000000bdf94f3d' },
  ],
};

// ── Patch engine ─────────────────────────────────────────────
function hexToBytes(hex) {
  const s = hex.replace(/[^0-9A-Fa-f]/g, '');
  if (s.length % 2 !== 0) return null;
  const b = Buffer.allocUnsafe(s.length / 2);
  for (let i = 0; i < s.length; i += 2) b[i >> 1] = parseInt(s.substr(i, 2), 16);
  return b;
}
function applyHexPatch(buf, findHex, replaceHex) {
  const search  = hexToBytes(findHex);
  const replace = hexToBytes(replaceHex);
  if (!search || !replace) return 0;
  let count = 0;
  for (let i = 0; i <= buf.length - search.length; i++) {
    let ok = true;
    for (let j = 0; j < search.length; j++) if (buf[i + j] !== search[j]) { ok = false; break; }
    if (ok) {
      const wl = Math.min(replace.length, buf.length - i);
      replace.copy(buf, i, 0, wl);
      count++; i += wl - 1;
    }
  }
  return count;
}
function applyBones(buf) {
  let count = 0;
  for (const bone of AIM_BODY_BONES) {
    const search  = Buffer.from(bone, 'latin1');
    const replace = Buffer.alloc(bone.length, 0);
    for (let i = 0; i <= buf.length - search.length; i++) {
      if (buf.subarray(i, i + search.length).equals(search)) {
        replace.copy(buf, i); count++; i += search.length - 1;
      }
    }
  }
  return count;
}

// ── Express app ──────────────────────────────────────────────
const app    = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Serve HTML tools — tự nhúng đúng origin vào API_BASE
const fs = require('fs');
function serveInjected(file, apiVar) {
  return (req, res) => {
    const proto = req.headers['x-forwarded-proto'] || 'http';
    const host  = req.headers['x-forwarded-host'] || req.headers.host || ('localhost:' + PORT);
    const origin = proto + '://' + host;
    let html = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
    html = html.replace(apiVar, "'" + origin + "/api'");
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  };
}
app.get('/api/tool',  serveInjected('tool.html',  "'http://localhost:3000/api'"));
app.get('/api/admin', serveInjected('admin.html', "'http://localhost:3000/api'"));
app.get('/api/healthz', (_req, res) => res.json({ status: 'ok' }));

// ── AUTH ─────────────────────────────────────────────────────
app.post('/api/auth/setup', async (req, res) => {
  const existing = db.prepare('SELECT id FROM admins LIMIT 1').get();
  if (existing) return res.status(403).json({ error: 'Admin đã được thiết lập' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu username hoặc password' });
  const hash = await bcrypt.hash(password, 12);
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?,?)').run(username, hash);
  console.log(`[SETUP] Admin tạo thành công: ${username}`);
  res.json({ ok: true, username });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu thông tin đăng nhập' });
  const admin = db.prepare('SELECT * FROM admins WHERE username=?').get(username);
  if (!admin || !(await bcrypt.compare(password, admin.password_hash)))
    return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  const accessToken  = signAccess(admin.id, admin.username);
  const refreshToken = signRefresh(admin.id);
  const expiresAt = new Date(Date.now() + 30 * 864e5).toISOString();
  db.prepare('INSERT INTO refresh_tokens (token, admin_id, expires_at) VALUES (?,?,?)').run(refreshToken, admin.id, expiresAt);
  res.json({ accessToken, refreshToken });
});

app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Thiếu refresh token' });
  const payload = verifyRefresh(refreshToken);
  if (!payload) return res.status(401).json({ error: 'Refresh token không hợp lệ' });
  const stored = db.prepare('SELECT * FROM refresh_tokens WHERE token=?').get(refreshToken);
  if (!stored || new Date(stored.expires_at) < new Date()) return res.status(401).json({ error: 'Refresh token hết hạn' });
  const admin = db.prepare('SELECT * FROM admins WHERE id=?').get(payload.adminId);
  if (!admin) return res.status(401).json({ error: 'Admin không tồn tại' });
  res.json({ accessToken: signAccess(admin.id, admin.username) });
});

app.post('/api/auth/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) db.prepare('DELETE FROM refresh_tokens WHERE token=?').run(refreshToken);
  res.json({ ok: true });
});

// ── KEY STATS / LOGS ─────────────────────────────────────────
app.get('/api/keys/stats', requireAdmin, (_req, res) => {
  const now = Date.now();
  const all = db.prepare('SELECT * FROM keys').all();
  res.json({
    total:  all.length,
    active: all.filter(k => k.active && (k.expiry === 0 || k.expiry > now)).length,
    vip:    all.filter(k => k.type === 'VIP').length,
  });
});

app.get('/api/keys/logs', requireAdmin, (_req, res) => {
  const logs = db.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT 100').all();
  res.json({ logs: logs.map(l => ({ ...l, ts: new Date(l.ts).getTime() })) });
});

// ── KEYS CRUD ────────────────────────────────────────────────
app.get('/api/keys', requireAdmin, (req, res) => {
  const filter = req.query.filter ?? 'all';
  const q      = (req.query.q ?? '').toLowerCase();
  const now    = Date.now();
  let rows = db.prepare('SELECT * FROM keys ORDER BY id DESC').all();
  if (q) rows = rows.filter(k => k.value.toLowerCase().includes(q) || k.note.toLowerCase().includes(q));
  if (filter === 'active') rows = rows.filter(k => k.active && (k.expiry === 0 || k.expiry > now));
  if (filter === 'locked') rows = rows.filter(k => !k.active || (k.expiry > 0 && k.expiry <= now));
  const allDevs = db.prepare('SELECT key_id, COUNT(*) as cnt FROM devices GROUP BY key_id').all();
  const devMap  = Object.fromEntries(allDevs.map(d => [d.key_id, d.cnt]));
  res.json({
    keys: rows.map(k => ({
      id: k.id, v: k.value, t: k.type, a: !!k.active, e: k.expiry,
      mu: k.max_uses, u: k.uses, md: k.max_devices, deviceCount: devMap[k.id] ?? 0, note: k.note,
    })),
  });
});

app.post('/api/keys', requireAdmin, (req, res) => {
  const { prefix = 'JERRY-', type = 'FREE', randLen = 8, days = 0, count = 1,
          maxDevices = 1, maxUses = 0, note = '', toolType = 'Make Data' } = req.body;
  const safeCount = Math.min(Math.max(+count, 1), 50);
  const safeLen   = Math.min(Math.max(+randLen, 4), 20);
  const expiry    = +days > 0 ? Date.now() + +days * 864e5 : 0;
  const stmt = db.prepare('INSERT INTO keys (value,type,active,expiry,max_devices,max_uses,note,tool_type) VALUES (?,?,1,?,?,?,?,?)');
  const created = [];
  for (let i = 0; i < safeCount; i++) {
    const value = prefix + randStr(safeLen);
    stmt.run(value, type, expiry, +maxDevices, +maxUses, note, toolType);
    created.push({ v: value });
  }
  addLog(`Tạo ${safeCount} key`, { ip: getIp(req), message: `Loại: ${type}, Hạn: ${days} ngày` });
  res.json({ success: true, created });
});

app.put('/api/keys/:id/toggle', requireAdmin, (req, res) => {
  const id  = +req.params.id;
  const key = db.prepare('SELECT * FROM keys WHERE id=?').get(id);
  if (!key) return res.status(404).json({ error: 'Key không tồn tại' });
  db.prepare('UPDATE keys SET active=? WHERE id=?').run(key.active ? 0 : 1, id);
  addLog(key.active ? 'Khóa key' : 'Mở khóa key', { keyVal: key.value, keyId: id, ip: getIp(req) });
  res.json({ ok: true, active: !key.active });
});

app.put('/api/keys/:id/extend', requireAdmin, (req, res) => {
  const id  = +req.params.id;
  const key = db.prepare('SELECT * FROM keys WHERE id=?').get(id);
  if (!key) return res.status(404).json({ error: 'Key không tồn tại' });
  const days = +(req.body.days ?? 30);
  const base = key.expiry > 0 && key.expiry > Date.now() ? key.expiry : Date.now();
  db.prepare('UPDATE keys SET expiry=? WHERE id=?').run(base + days * 864e5, id);
  addLog(`Gia hạn +${days} ngày`, { keyVal: key.value, keyId: id, ip: getIp(req) });
  res.json({ ok: true });
});

app.put('/api/keys/:id/reset', requireAdmin, (req, res) => {
  const id  = +req.params.id;
  const key = db.prepare('SELECT * FROM keys WHERE id=?').get(id);
  if (!key) return res.status(404).json({ error: 'Key không tồn tại' });
  db.prepare('UPDATE keys SET uses=0 WHERE id=?').run(id);
  addLog('Reset lượt sử dụng về 0', { keyVal: key.value, keyId: id, ip: getIp(req) });
  res.json({ ok: true });
});

app.delete('/api/keys/:id', requireAdmin, (req, res) => {
  const id  = +req.params.id;
  const key = db.prepare('SELECT * FROM keys WHERE id=?').get(id);
  if (!key) return res.status(404).json({ error: 'Key không tồn tại' });
  db.prepare('DELETE FROM devices WHERE key_id=?').run(id);
  db.prepare('DELETE FROM keys WHERE id=?').run(id);
  addLog('Xóa key', { keyVal: key.value, keyId: id, ip: getIp(req) });
  res.json({ ok: true });
});

app.get('/api/keys/:id/devices', requireAdmin, (req, res) => {
  const devs = db.prepare('SELECT * FROM devices WHERE key_id=? ORDER BY last_seen DESC').all(+req.params.id);
  res.json({ devices: devs.map(d => ({ ...d, last_seen: new Date(d.last_seen).getTime() })) });
});

app.delete('/api/keys/:id/devices/:devId', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM devices WHERE id=? AND key_id=?').run(+req.params.devId, +req.params.id);
  res.json({ ok: true });
});

app.delete('/api/keys/:id/devices', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM devices WHERE key_id=?').run(+req.params.id);
  res.json({ ok: true });
});

// ── KEY VALIDATION ────────────────────────────────────────────
function resolveKey(keyVal) {
  const key = db.prepare('SELECT * FROM keys WHERE value=?').get(keyVal);
  if (!key)        return { ok: false, status: 403, error: 'Mã khóa không tồn tại hoặc sai định dạng!' };
  if (!key.active) return { ok: false, status: 403, error: 'Giấy phép bị quản trị viên khóa!' };
  if (key.expiry > 0 && Date.now() > key.expiry) return { ok: false, status: 403, error: 'Giấy phép đã hết hạn!' };
  if (key.max_uses > 0 && key.uses >= key.max_uses) return { ok: false, status: 403, error: 'Key đã đạt giới hạn lượt sử dụng!' };
  return { ok: true, key };
}

app.post('/api/validate-key', (req, res) => {
  const { key: keyVal, fingerprint: clientFp } = req.body;
  if (!keyVal) return res.status(400).json({ success: false, error: 'Thiếu mã key' });
  const ip = getIp(req);
  const fp = clientFp ?? fingerprint(req);
  const r  = resolveKey(keyVal);
  if (!r.ok) {
    addLog('Xác thực key thất bại', { keyVal, success: 0, ip, message: r.error });
    return res.status(r.status).json({ success: false, error: r.error });
  }
  const { key } = r;
  if (key.tool_type !== 'Make Data')
    return res.status(403).json({ success: false, error: 'Khóa này dành cho phân hệ khác!' });
  const devs   = db.prepare('SELECT * FROM devices WHERE key_id=?').all(key.id);
  const exists = devs.find(d => d.fingerprint === fp);
  if (!exists) {
    if (devs.length >= key.max_devices) {
      addLog('Xác thực key thất bại', { keyVal, keyId: key.id, success: 0, ip, message: 'Vượt giới hạn thiết bị' });
      return res.status(403).json({ success: false, error: `Key đã đạt giới hạn ${key.max_devices} thiết bị!` });
    }
    db.prepare('INSERT INTO devices (key_id, fingerprint, ip) VALUES (?,?,?)').run(key.id, fp, ip);
    db.prepare('UPDATE keys SET uses=uses+1 WHERE id=?').run(key.id);
  } else {
    db.prepare("UPDATE devices SET last_seen=datetime('now'), ip=? WHERE id=?").run(ip, exists.id);
  }
  addLog('Xác thực key thành công', { keyVal, keyId: key.id, ip });
  res.json({ success: true, type: key.type, toolType: key.tool_type, expiry: key.expiry });
});

// ── SERVER-SIDE PATCH (hex không bao giờ ra client) ──────────
app.post('/api/patch-file', upload.single('file'), (req, res) => {
  const { key: keyVal, patchIds: rawIds, section } = req.body;
  if (!keyVal)    return res.status(400).json({ error: 'Thiếu mã key' });
  if (!req.file)  return res.status(400).json({ error: 'Thiếu file cần patch' });
  if (!rawIds)    return res.status(400).json({ error: 'Thiếu danh sách patch' });
  let patchIds;
  try { patchIds = JSON.parse(rawIds); } catch { return res.status(400).json({ error: 'patchIds không hợp lệ' }); }
  if (!Array.isArray(patchIds) || !patchIds.length) return res.status(400).json({ error: 'Chưa chọn patch nào' });

  const r = resolveKey(keyVal);
  if (!r.ok) return res.status(r.status).json({ error: r.error });
  if (r.key.tool_type !== 'Make Data')
    return res.status(403).json({ error: 'Khóa này dành cho phân hệ khác!' });

  const buf = Buffer.from(req.file.buffer);
  let total = 0;

  if (section === 'avatar') {
    for (const id of patchIds) {
      const pairs = HEX_CONFIG[id];
      if (!pairs) continue;
      for (const p of pairs) total += applyHexPatch(buf, p.find, p.replace);
    }
  } else if (section === 'cache') {
    for (const id of patchIds) {
      if (+id === 1) {
        total += applyBones(buf);
        const pairs = CACHE_HEX_CONFIG[1];
        if (pairs) for (const p of pairs) total += applyHexPatch(buf, p.find, p.replace);
      } else {
        const pairs = CACHE_HEX_CONFIG[id];
        if (!pairs) continue;
        for (const p of pairs) total += applyHexPatch(buf, p.find, p.replace);
      }
    }
  }

  addLog(`Patch file (${section}, ids:${patchIds.join(',')})`, {
    keyVal, keyId: r.key.id, success: total > 0, ip: getIp(req),
    message: total > 0 ? `${total} vị trí đã patch` : 'Không tìm thấy vị trí hex',
  });

  if (total === 0)
    return res.status(422).json({ error: 'Không tìm thấy vị trí Hex trong file. Kiểm tra lại file hoặc lựa chọn patch.' });

  const outName = 'mod_' + req.file.originalname;
  res.set({ 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${outName}"`, 'X-Patch-Count': String(total) });
  res.send(buf);
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════╗');
  console.log(`  ║   Jerry Mod TOOL Pro — Server v1.9  ║`);
  console.log(`  ║   http://localhost:${PORT}              ║`);
  console.log('  ╚══════════════════════════════════════╝');
  console.log('');
  console.log('  Tool:  http://localhost:' + PORT + '/api/tool');
  console.log('  Admin: http://localhost:' + PORT + '/api/admin');
  console.log('');
  const hasAdmin = db.prepare('SELECT id FROM admins LIMIT 1').get();
  if (!hasAdmin) {
    console.log('  ⚠️  Chưa có admin! Truy cập /api/admin → "Tạo admin lần đầu"');
    console.log('     hoặc gọi: POST /api/auth/setup  { username, password }');
  }
  console.log('');
});
