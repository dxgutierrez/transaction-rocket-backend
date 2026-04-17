'use strict';
const express  = require('express');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');
const crypto   = require('crypto');
const fs       = require('fs');

const PORT       = process.env.PORT || 3000;
const DATA_DIR   = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH    = path.join(DATA_DIR, 'rocket.db');
const JWT_SECRET = process.env.SESSION_SECRET || (() => {
  console.warn('⚠️  SESSION_SECRET not set — using random key. Set it in Render environment variables!');
  return crypto.randomBytes(64).toString('hex');
})();
const IS_PROD = process.env.NODE_ENV === 'production';

// Warn if secret is too short
if (JWT_SECRET.length < 32) console.warn('⚠️  SESSION_SECRET is too short — use at least 32 random characters');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Database ──────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL DEFAULT (datetime('now')),
    user_id    TEXT,
    user_email TEXT,
    action     TEXT NOT NULL,
    ip         TEXT,
    detail     TEXT
  );
`);

const stmtGet      = db.prepare('SELECT value FROM store WHERE key = ?');
const stmtSet      = db.prepare("INSERT OR REPLACE INTO store (key, value, updated_at) VALUES (?, ?, datetime('now'))");
const stmtAudit    = db.prepare("INSERT INTO audit_log (user_id, user_email, action, ip, detail) VALUES (?, ?, ?, ?, ?)");
const stmtAuditGet = db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200");

function dbGet(key, fallback = null) {
  const row = stmtGet.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}
function dbSet(key, value) { stmtSet.run(key, JSON.stringify(value)); }

function audit(userId, email, action, ip, detail = '') {
  try { stmtAudit.run(userId || null, email || null, action, ip || null, detail || null); } catch(e) {}
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
}

// ── Rate limiter (in-memory, per IP) ─────────────────────────────────
// Tracks failed login attempts. After 5 failures → 15 min lockout.
const loginAttempts = new Map(); // ip → { count, lockedUntil }
const MAX_ATTEMPTS  = 5;
const LOCKOUT_MS    = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const now  = Date.now();
  const rec  = loginAttempts.get(ip);
  if (!rec) return { allowed: true };
  if (rec.lockedUntil && now < rec.lockedUntil) {
    const mins = Math.ceil((rec.lockedUntil - now) / 60000);
    return { allowed: false, retryAfter: mins };
  }
  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0 };
  rec.count++;
  if (rec.count >= MAX_ATTEMPTS) {
    rec.lockedUntil = now + LOCKOUT_MS;
    rec.count = 0;
  }
  loginAttempts.set(ip, rec);
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

// Clean up stale records every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts.entries()) {
    if (!rec.lockedUntil || now > rec.lockedUntil) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ── Input sanitization ────────────────────────────────────────────────
function sanitize(val) {
  if (typeof val !== 'string') return val;
  return val
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function sanitizeDeep(obj) {
  if (typeof obj === 'string') return sanitize(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeDeep);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      // Don't sanitize known URL fields or hashed passwords
      if (['commandLink','transactionDeskLink','link','url','pdfData','fileDataUrl','password'].includes(k)) {
        out[k] = v;
      } else {
        out[k] = sanitizeDeep(v);
      }
    }
    return out;
  }
  return obj;
}

// ── Seed data ─────────────────────────────────────────────────────────
const PERSISTENT_KEYS = [
  'transactions','contacts','users','templates','phases','customEvents',
  'documents','emailTemplates','savedViews','dailyActivity','chatSpaces',
  'quickLinks','onboardingItems','teamChatWebhook','agentView','agentGoals'
];

const SEED_USERS = [
  { id:'u1', name:'Daniel Gutierrez', email:'dxgutierrez@kw.com', password:'admin123', role:'owner', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
  { id:'u2', name:'Rachelle', email:'operations@bidwichita.com', password:'rachelle123', role:'operations', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
  { id:'u5', name:'Angel Perez', email:'transactions@bidwichita.com', password:'angel123', role:'agent', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
  { id:'u3', name:'Jesus', email:'listings@bidwichita.com', password:'auction123', role:'agent', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
  { id:'u4', name:'Sophia', email:'sophia@bidwichita.com', password:'auction123', role:'marketing', active:true, chatWebhook:'', perms:{dashboard:true,transactions:false,contacts:false,calendar:true,tasks:true,marketing:true,production:false,documents:false,settings:false,onboarding:false} }
];

const DEFAULT_SEED = {
  transactions:[],contacts:[],users:SEED_USERS,templates:{},phases:{},customEvents:[],documents:[],
  emailTemplates:[],savedViews:[],dailyActivity:{},teamChatWebhook:'',agentView:'Daniel Gutierrez',
  chatSpaces:[{id:'cs1',name:'Team Space',url:'',type:'team'},{id:'cs2',name:'Closing Space',url:'',type:'closing'},{id:'cs3',name:'Marketing Space',url:'',type:'marketing'},{id:'cs4',name:'Admin Space',url:'',type:'admin'}],
  quickLinks:[{id:'ql1',label:'KW Command',url:'https://agent.kw.com',color:'#B42318'},{id:'ql2',label:'Authentisign',url:'https://app.authentisign.com',color:'#1D4ED8'},{id:'ql3',label:'Paragon MLS',url:'https://paragonrels.com',color:'#027A48'},{id:'ql4',label:'BidWichita',url:'https://bidwichita.com',color:'#7C3AED'}],
  onboardingItems:null,
  agentGoals:{}
};

// Seed only truly missing keys — never overwrite existing data
let seededCount = 0;
for (const key of PERSISTENT_KEYS) {
  if (!stmtGet.get(key)) {
    dbSet(key, DEFAULT_SEED[key] ?? null);
    seededCount++;
  }
}
if (seededCount === PERSISTENT_KEYS.length) {
  console.log('📦 Fresh database — all keys seeded with defaults');
} else if (seededCount > 0) {
  console.log(`📦 Seeded ${seededCount} missing keys (existing data preserved)`);
} else {
  // Existing database — log what we have
  const txnCount = (dbGet('transactions', [])).length;
  const conCount = (dbGet('contacts', [])).length;
  const usrCount = (dbGet('users', [])).length;
  console.log(`✅ Existing database loaded — ${txnCount} transactions, ${conCount} contacts, ${usrCount} users`);
}

// ── Express ───────────────────────────────────────────────────────────
const app = express();

// ── Security headers (item 3) ─────────────────────────────────────────
app.use((req, res, next) => {
  // Force HTTPS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // XSS filter (legacy browsers)
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Content Security Policy — restricts what can load
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self' https://chat.googleapis.com https://fonts.googleapis.com https://fonts.gstatic.com; " +
    "frame-ancestors 'none';"
  );
  // Don't send referrer outside origin
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Disable browser features we don't use
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // Remove fingerprinting header
  res.removeHeader('X-Powered-By');
  next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Password hashing ──────────────────────────────────────────────────
function hashPassword(plain) {
  if (!plain) return '';
  if (/^[a-f0-9]{64}$/i.test(plain)) return plain;
  return crypto.createHash('sha256').update(plain).digest('hex');
}
function isHashed(pw) { return /^[a-f0-9]{64}$/i.test(pw); }

// ── Password complexity check (item 7) ───────────────────────────────
function checkPasswordComplexity(pw) {
  if (!pw || pw.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(pw))    return 'Password must contain at least one uppercase letter';
  if (!/[0-9]/.test(pw))    return 'Password must contain at least one number';
  return null; // null = valid
}

const DEFAULT_PLAINTEXT = new Set(['admin123','rachelle123','auction123','angel123']);

function getToken(req) {
  const h = req.headers.authorization;
  return (h && h.startsWith('Bearer ')) ? h.slice(7) : null;
}

function requireAuth(req, res, next) {
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    req.userId = p.userId;
    next();
  } catch(e) {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const token = getToken(req);
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    try {
      const p = jwt.verify(token, JWT_SECRET);
      req.userId = p.userId;
      const user = dbGet('users',[]).find(u => u.id === req.userId);
      if (!user) return res.status(401).json({ error: 'User not found' });
      if (!roles.includes(user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
      req.user = user;
      next();
    } catch(e) {
      res.status(401).json({ error: 'Session expired — please log in again' });
    }
  };
}

// ── API: Auth (with rate limiting — item 1) ───────────────────────────
app.post('/api/login', (req, res) => {
  const ip = getClientIp(req);

  // Check rate limit
  const limit = checkRateLimit(ip);
  if (!limit.allowed) {
    audit(null, req.body?.email, 'LOGIN_BLOCKED', ip, `Rate limited — try again in ${limit.retryAfter} min`);
    return res.status(429).json({
      error: `Too many failed attempts. Please try again in ${limit.retryAfter} minute${limit.retryAfter !== 1 ? 's' : ''}.`
    });
  }

  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const users  = dbGet('users', []);
  const hashed = hashPassword(password);
  const user   = users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() && u.active &&
    (u.password === hashed || (!isHashed(u.password) && u.password === password))
  );

  if (!user) {
    recordFailedAttempt(ip);
    audit(null, email, 'LOGIN_FAILED', ip, 'Invalid credentials');
    const rec = loginAttempts.get(ip);
    const remaining = rec ? Math.max(0, MAX_ATTEMPTS - rec.count) : MAX_ATTEMPTS;
    return res.status(401).json({
      error: 'Invalid email or password',
      attemptsRemaining: remaining
    });
  }

  // Successful login — clear failed attempts
  clearAttempts(ip);

  // Upgrade plain-text password to hash
  if (!isHashed(user.password)) {
    user.password = hashed;
    dbSet('users', users.map(u => u.id === user.id ? user : u));
  }

  const forceChange = DEFAULT_PLAINTEXT.has(password) || !!user._forcePasswordChange;
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

  audit(user.id, user.email, 'LOGIN_SUCCESS', ip);
  console.log('Login OK:', user.email, 'from', ip);

  const { password: _pw, ...safeUser } = user;
  res.json({ user: safeUser, token, forcePasswordChange: forceChange });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const user = dbGet('users',[]).find(u => u.id === req.userId);
  audit(req.userId, user?.email, 'LOGOUT', getClientIp(req));
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = dbGet('users',[]).find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _pw, ...safe } = user;
  res.json(safe);
});

// ── API: State ────────────────────────────────────────────────────────
app.get('/api/state', requireAuth, (req, res) => {
  const state = {};
  for (const key of PERSISTENT_KEYS) state[key] = dbGet(key);
  if (state.users) state.users = state.users.map(({ password: _pw, ...u }) => u);
  res.json(state);
});

app.post('/api/state', requireAuth, (req, res) => {
  // Sanitize all incoming data before saving (item 4)
  const sanitized = sanitizeDeep(req.body);
  db.transaction(() => {
    for (const key of PERSISTENT_KEYS) {
      if (!(key in sanitized)) continue;
      if (key === 'users') {
        const existing = dbGet('users', []);
        const incoming = sanitized.users || [];
        const merged = incoming.map(u => ({
          ...u,
          password: (existing.find(e => e.id === u.id) || {}).password || hashPassword('changeme')
        }));
        existing.forEach(ex => { if (!merged.find(m => m.id === ex.id)) merged.push(ex); });
        dbSet('users', merged);
      } else {
        dbSet(key, sanitized[key]);
      }
    }
  })();
  res.json({ ok: true });
});

// ── API: Users ────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  res.json(dbGet('users',[]).map(({ password: _pw, ...u }) => u));
});

app.post('/api/users', requireRole('owner','operations'), (req, res) => {
  const users = dbGet('users', []);
  const { name, email, password } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  if (!password) return res.status(400).json({ error: 'Password required' });
  // Enforce complexity (item 7)
  const pwErr = checkPasswordComplexity(password);
  if (pwErr) return res.status(400).json({ error: pwErr });
  // Check email not already in use
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'Email already in use' });
  }
  const nu = { ...req.body, id: 'u' + Date.now(), password: hashPassword(password) };
  dbSet('users', [...users, nu]);
  audit(req.userId, null, 'USER_CREATED', getClientIp(req), email);
  const { password: _pw, ...safe } = nu;
  res.json(safe);
});

app.put('/api/users/:id', requireRole('owner','operations'), (req, res) => {
  const users  = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner')
    return res.status(403).json({ error: 'Cannot edit Owner accounts' });
  const data = { ...target, ...req.body };
  if (req.body.password && req.body.password.length >= 1) {
    const pwErr = checkPasswordComplexity(req.body.password);
    if (pwErr) return res.status(400).json({ error: pwErr });
    data.password = hashPassword(req.body.password);
  } else {
    data.password = target.password;
  }
  dbSet('users', users.map(u => u.id === req.params.id ? data : u));
  audit(req.userId, null, 'USER_UPDATED', getClientIp(req), target.email);
  const { password: _pw, ...safe } = data;
  res.json(safe);
});

app.delete('/api/users/:id', requireRole('owner'), (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
  const target = dbGet('users',[]).find(u => u.id === req.params.id);
  dbSet('users', dbGet('users',[]).filter(u => u.id !== req.params.id));
  audit(req.userId, null, 'USER_DELETED', getClientIp(req), target?.email);
  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', requireRole('owner','operations'), (req, res) => {
  const { password } = req.body;
  const pwErr = checkPasswordComplexity(password);
  if (pwErr) return res.status(400).json({ error: pwErr });
  const users  = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner')
    return res.status(403).json({ error: 'Cannot reset Owner passwords' });
  dbSet('users', users.map(u =>
    u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: true } : u
  ));
  audit(req.userId, null, 'PASSWORD_RESET', getClientIp(req), target.email);
  console.log('Password reset:', target.email);
  res.json({ ok: true });
});

app.post('/api/users/:id/change-password', requireAuth, (req, res) => {
  const { password } = req.body;
  const pwErr = checkPasswordComplexity(password);
  if (pwErr) return res.status(400).json({ error: pwErr });
  const isSelf  = req.userId === req.params.id;
  const reqUser = dbGet('users',[]).find(u => u.id === req.userId);
  if (!isSelf && !['owner','operations'].includes(reqUser?.role))
    return res.status(403).json({ error: 'Insufficient permissions' });
  const target = dbGet('users',[]).find(u => u.id === req.params.id);
  dbSet('users', dbGet('users',[]).map(u =>
    u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: false } : u
  ));
  audit(req.userId, target?.email, 'PASSWORD_CHANGED', getClientIp(req));
  res.json({ ok: true });
});

// ── API: Audit log (item 6) — Owner only ─────────────────────────────
app.get('/api/audit', requireRole('owner'), (req, res) => {
  const logs = stmtAuditGet.all();
  res.json(logs);
});

// ── API: Health ───────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const txns = dbGet('transactions',[]);
  const cons  = dbGet('contacts',[]);
  res.json({
    status: 'ok',
    transactions: txns.length,
    contacts: cons.length,
    fingerprint: `${txns.length}-${cons.length}-${txns[txns.length-1]?.id||0}-${cons[cons.length-1]?.id||0}`,
    uptime: Math.round(process.uptime()),
    auth: 'JWT'
  });
});

app.get('/api/session-check', (req, res) => {
  const token = getToken(req);
  if (!token) return res.json({ authenticated:false, reason:'No Bearer token' });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    res.json({ authenticated:true, userId:p.userId, expires:new Date(p.exp*1000) });
  } catch(e) {
    res.json({ authenticated:false, reason:e.message });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Automatic daily backup ───────────────────────────────────────────
function runBackup() {
  try {
    const backupDir = path.join(DATA_DIR, 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const backupPath = path.join(backupDir, `backup-${date}.json`);

    // Don't overwrite if already backed up today
    if (fs.existsSync(backupPath)) return;

    const backup = {};
    for (const key of PERSISTENT_KEYS) {
      backup[key] = dbGet(key);
    }
    backup._meta = {
      backedUpAt: new Date().toISOString(),
      transactions: (backup.transactions || []).length,
      contacts: (backup.contacts || []).length,
      users: (backup.users || []).length,
    };

    fs.writeFileSync(backupPath, JSON.stringify(backup, null, 2));
    console.log(`💾 Daily backup saved: ${backupPath} (${(backup.transactions||[]).length} txns, ${(backup.contacts||[]).length} contacts)`);

    // Keep only last 30 backups
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('backup-') && f.endsWith('.json'))
      .sort();
    if (files.length > 30) {
      const toDelete = files.slice(0, files.length - 30);
      toDelete.forEach(f => {
        try { fs.unlinkSync(path.join(backupDir, f)); } catch(e) {}
      });
    }
  } catch(e) {
    console.warn('Backup failed:', e.message);
  }
}

// ── Backup restore API (Owner only) ──────────────────────────────────
app.get('/api/backups', requireRole('owner'), (req, res) => {
  try {
    const backupDir = path.join(DATA_DIR, 'backups');
    if (!fs.existsSync(backupDir)) return res.json([]);
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('backup-') && f.endsWith('.json'))
      .sort()
      .reverse(); // newest first
    const list = files.map(f => {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(backupDir, f), 'utf8'));
        return { filename: f, meta: data._meta || {} };
      } catch { return { filename: f, meta: {} }; }
    });
    res.json(list);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/backups/restore/:filename', requireRole('owner'), (req, res) => {
  try {
    const backupDir = path.join(DATA_DIR, 'backups');
    const filename  = req.params.filename.replace(/[^a-zA-Z0-9\-\.]/g, ''); // sanitize
    const backupPath = path.join(backupDir, filename);
    if (!fs.existsSync(backupPath)) return res.status(404).json({ error: 'Backup not found' });
    const data = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
    // Save a safety backup of current state before restoring
    runBackup();
    db.transaction(() => {
      for (const key of PERSISTENT_KEYS) {
        if (key in data) dbSet(key, data[key]);
      }
    })();
    console.log('🔄 Restored from backup:', filename);
    res.json({ ok: true, restored: filename });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Transaction Rocket on port ${PORT} | Auth: JWT | DB: ${DB_PATH}`);
  if (!process.env.SESSION_SECRET) console.warn('⚠️  Set SESSION_SECRET in Render environment!');

  // Run backup on startup then every 24 hours
  runBackup();
  setInterval(runBackup, 24 * 60 * 60 * 1000);
});
