'use strict';
const express  = require('express');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path     = require('path');
const crypto   = require('crypto');
const fs       = require('fs');

const PORT        = process.env.PORT || 3000;
const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH     = path.join(DATA_DIR, 'rocket.db');
const JWT_SECRET  = process.env.SESSION_SECRET || 'change-me-' + crypto.randomBytes(16).toString('hex');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT (datetime('now')));`);

const stmtGet = db.prepare('SELECT value FROM store WHERE key = ?');
const stmtSet = db.prepare("INSERT OR REPLACE INTO store (key, value, updated_at) VALUES (?, ?, datetime('now'))");

function dbGet(key, fallback = null) {
  const row = stmtGet.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}
function dbSet(key, value) { stmtSet.run(key, JSON.stringify(value)); }

const PERSISTENT_KEYS = ['transactions','contacts','users','templates','phases','customEvents','documents','emailTemplates','savedViews','dailyActivity','chatSpaces','quickLinks','onboardingItems','teamChatWebhook','agentView'];

const SEED_USERS = [
  { id:'u1', name:'Daniel Gutierrez', email:'dxgutierrez@kw.com', password:'admin123', role:'owner', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
  { id:'u2', name:'Rachelle', email:'operations@bidwichita.com', password:'rachelle123', role:'operations', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
  { id:'u5', name:'Angel Perez', email:'transactions@bidwichita.com', password:'angel123', role:'agent', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
  { id:'u3', name:'Jesus', email:'listings@bidwichita.com', password:'auction123', role:'agent', active:true, chatWebhook:'', perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
  { id:'u4', name:'Sophia', email:'sophia@bidwichita.com', password:'auction123', role:'marketing', active:true, chatWebhook:'', perms:{dashboard:true,transactions:false,contacts:false,calendar:true,tasks:true,marketing:true,production:false,documents:false,settings:false,onboarding:false} }
];

const DEFAULT_SEED = {
  transactions:[],contacts:[],users:SEED_USERS,templates:{},phases:{},customEvents:[],documents:[],emailTemplates:[],savedViews:[],dailyActivity:{},teamChatWebhook:'',agentView:'Daniel Gutierrez',
  chatSpaces:[{id:'cs1',name:'Team Space',url:'',type:'team'},{id:'cs2',name:'Closing Space',url:'',type:'closing'},{id:'cs3',name:'Marketing Space',url:'',type:'marketing'},{id:'cs4',name:'Admin Space',url:'',type:'admin'}],
  quickLinks:[{id:'ql1',label:'KW Command',url:'https://agent.kw.com',color:'#B42318'},{id:'ql2',label:'Authentisign',url:'https://app.authentisign.com',color:'#1D4ED8'},{id:'ql3',label:'Paragon MLS',url:'https://paragonrels.com',color:'#027A48'},{id:'ql4',label:'BidWichita',url:'https://bidwichita.com',color:'#7C3AED'}],
  onboardingItems:null
};

for (const key of PERSISTENT_KEYS) {
  if (!stmtGet.get(key)) dbSet(key, DEFAULT_SEED[key] ?? null);
}

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function hashPassword(plain) {
  if (!plain) return '';
  if (/^[a-f0-9]{64}$/i.test(plain)) return plain;
  return crypto.createHash('sha256').update(plain).digest('hex');
}
function isHashed(pw) { return /^[a-f0-9]{64}$/i.test(pw); }

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

// ── Auth routes ───────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = dbGet('users', []);
  const hashed = hashPassword(password);
  const user = users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() && u.active &&
    (u.password === hashed || (!isHashed(u.password) && u.password === password))
  );
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  if (!isHashed(user.password)) {
    user.password = hashed;
    dbSet('users', users.map(u => u.id === user.id ? user : u));
  }
  const forceChange = DEFAULT_PLAINTEXT.has(password) || !!user._forcePasswordChange;
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  console.log('Login OK:', user.email);
  const { password: _pw, ...safeUser } = user;
  res.json({ user: safeUser, token, forcePasswordChange: forceChange });
});

app.post('/api/logout', (req, res) => res.json({ ok: true }));

app.get('/api/me', requireAuth, (req, res) => {
  const user = dbGet('users',[]).find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _pw, ...safe } = user;
  res.json(safe);
});

// ── State ─────────────────────────────────────────────────────────────
app.get('/api/state', requireAuth, (req, res) => {
  const state = {};
  for (const key of PERSISTENT_KEYS) state[key] = dbGet(key);
  if (state.users) state.users = state.users.map(({ password: _pw, ...u }) => u);
  res.json(state);
});

app.post('/api/state', requireAuth, (req, res) => {
  db.transaction(() => {
    for (const key of PERSISTENT_KEYS) {
      if (!(key in req.body)) continue;
      if (key === 'users') {
        const existing = dbGet('users', []);
        const incoming = req.body.users || [];
        const merged = incoming.map(u => ({ ...u, password: (existing.find(e => e.id === u.id) || {}).password || hashPassword('changeme') }));
        existing.forEach(ex => { if (!merged.find(m => m.id === ex.id)) merged.push(ex); });
        dbSet('users', merged);
      } else {
        dbSet(key, req.body[key]);
      }
    }
  })();
  res.json({ ok: true });
});

// ── Users ─────────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  res.json(dbGet('users',[]).map(({ password: _pw, ...u }) => u));
});

app.post('/api/users', requireRole('owner','operations'), (req, res) => {
  const users = dbGet('users', []);
  const { name, email, password } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  if (!password) return res.status(400).json({ error: 'Password required' });
  const nu = { ...req.body, id: 'u' + Date.now(), password: hashPassword(password) };
  dbSet('users', [...users, nu]);
  const { password: _pw, ...safe } = nu;
  res.json(safe);
});

app.put('/api/users/:id', requireRole('owner','operations'), (req, res) => {
  const users = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner') return res.status(403).json({ error: 'Cannot edit Owner accounts' });
  const data = { ...target, ...req.body };
  data.password = (req.body.password && req.body.password.length >= 8) ? hashPassword(req.body.password) : target.password;
  dbSet('users', users.map(u => u.id === req.params.id ? data : u));
  const { password: _pw, ...safe } = data;
  res.json(safe);
});

app.delete('/api/users/:id', requireRole('owner'), (req, res) => {
  if (req.params.id === req.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
  dbSet('users', dbGet('users',[]).filter(u => u.id !== req.params.id));
  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', requireRole('owner','operations'), (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Min 8 characters' });
  const users = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner') return res.status(403).json({ error: 'Cannot reset Owner passwords' });
  dbSet('users', users.map(u => u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: true } : u));
  console.log('Password reset:', target.email);
  res.json({ ok: true });
});

app.post('/api/users/:id/change-password', requireAuth, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Min 8 characters' });
  const isSelf = req.userId === req.params.id;
  const reqUser = dbGet('users',[]).find(u => u.id === req.userId);
  if (!isSelf && !['owner','operations'].includes(reqUser?.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  dbSet('users', dbGet('users',[]).map(u => u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: false } : u));
  res.json({ ok: true });
});

// ── Health / debug ────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const txns = dbGet('transactions',[]);
  const cons  = dbGet('contacts',[]);
  res.json({ status:'ok', transactions:txns.length, contacts:cons.length, fingerprint:`${txns.length}-${cons.length}-${txns[txns.length-1]?.id||0}-${cons[cons.length-1]?.id||0}`, uptime:Math.round(process.uptime()), auth:'JWT' });
});

app.get('/api/session-check', (req, res) => {
  const token = getToken(req);
  if (!token) return res.json({ authenticated:false, reason:'No Bearer token — check localStorage' });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    res.json({ authenticated:true, userId:p.userId, expires:new Date(p.exp*1000) });
  } catch(e) {
    res.json({ authenticated:false, reason:e.message });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`🚀 Transaction Rocket on port ${PORT} | Auth: JWT | DB: ${DB_PATH}`);
});
