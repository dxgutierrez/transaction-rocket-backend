'use strict';
const express    = require('express');
const session    = require('express-session');
const FileStore  = require('session-file-store')(session);
const Database   = require('better-sqlite3');
const path       = require('path');
const crypto     = require('crypto');
const fs         = require('fs');

// ── Config ────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH     = path.join(DATA_DIR, 'rocket.db');
const SESS_SECRET = process.env.SESSION_SECRET || 'change-me-' + crypto.randomBytes(16).toString('hex');
const IS_PROD     = process.env.NODE_ENV === 'production';

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Database setup ────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── DB helpers ────────────────────────────────────────────────────────
const stmtGet = db.prepare('SELECT value FROM store WHERE key = ?');
const stmtSet = db.prepare('INSERT OR REPLACE INTO store (key, value, updated_at) VALUES (?, ?, datetime(\'now\'))');

function dbGet(key, fallback = null) {
  const row = stmtGet.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}
function dbSet(key, value) {
  stmtSet.run(key, JSON.stringify(value));
}

// ── Seed data ─────────────────────────────────────────────────────────
const PERSISTENT_KEYS = [
  'transactions','contacts','users','templates','phases',
  'customEvents','documents','emailTemplates','savedViews',
  'dailyActivity','chatSpaces','quickLinks','onboardingItems',
  'teamChatWebhook','agentView'
];

const DEFAULT_SEED = {
  transactions: [], contacts: [], users: [
    { id:'u1', name:'Daniel Gutierrez', email:'dxgutierrez@kw.com',
      password:'admin123', role:'owner', active:true, chatWebhook:'',
      perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
    { id:'u2', name:'Rachelle', email:'operations@bidwichita.com',
      password:'rachelle123', role:'operations', active:true, chatWebhook:'',
      perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:true,production:true,documents:true,settings:true,onboarding:true} },
    { id:'u5', name:'Angel Perez', email:'transactions@bidwichita.com',
      password:'angel123', role:'agent', active:true, chatWebhook:'',
      perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
    { id:'u3', name:'Jesus', email:'listings@bidwichita.com',
      password:'auction123', role:'agent', active:true, chatWebhook:'',
      perms:{dashboard:true,transactions:true,contacts:true,calendar:true,tasks:true,marketing:false,production:false,documents:true,settings:false,onboarding:true} },
    { id:'u4', name:'Sophia', email:'sophia@bidwichita.com',
      password:'auction123', role:'marketing', active:true, chatWebhook:'',
      perms:{dashboard:true,transactions:false,contacts:false,calendar:true,tasks:true,marketing:true,production:false,documents:false,settings:false,onboarding:false} }
  ],
  templates:{}, phases:{}, customEvents:[], documents:[], emailTemplates:[],
  savedViews:[], dailyActivity:{}, teamChatWebhook:'', agentView:'Daniel Gutierrez',
  chatSpaces:[
    {id:'cs1',name:'Team Space',url:'',type:'team'},
    {id:'cs2',name:'Closing Space',url:'',type:'closing'},
    {id:'cs3',name:'Marketing Space',url:'',type:'marketing'},
    {id:'cs4',name:'Admin Space',url:'',type:'admin'}
  ],
  quickLinks:[
    {id:'ql1',label:'KW Command',url:'https://agent.kw.com',color:'#B42318'},
    {id:'ql2',label:'Authentisign',url:'https://app.authentisign.com',color:'#1D4ED8'},
    {id:'ql3',label:'Paragon MLS',url:'https://paragonrels.com',color:'#027A48'},
    {id:'ql4',label:'BidWichita',url:'https://bidwichita.com',color:'#7C3AED'}
  ],
  onboardingItems: null
};

for (const key of PERSISTENT_KEYS) {
  if (!stmtGet.get(key)) dbSet(key, DEFAULT_SEED[key] ?? null);
}

// ── Express + sessions (in-memory store — reliable, fine for 4 users) ─
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new FileStore({
    path: path.join(DATA_DIR, 'sessions'),
    ttl: 7 * 24 * 60 * 60,  // 7 days in seconds
    retries: 3,
    logFn: () => {}           // silence file store logs
  }),
  secret: SESS_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,   // Render terminates SSL at proxy — cookie travels HTTP internally
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  // Log for debugging
  console.warn('requireAuth failed — session:', JSON.stringify({
    id: req.sessionID,
    hasSession: !!req.session,
    userId: req.session?.userId,
    cookie: req.headers.cookie ? 'present' : 'missing'
  }));
  res.status(401).json({ error: 'Not authenticated' });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session?.userId) return res.status(401).json({ error: 'Not authenticated' });
    const users = dbGet('users', []);
    const user  = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (!roles.includes(user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    req.user = user;
    next();
  };
}

// ── Password hashing ──────────────────────────────────────────────────
function hashPassword(plain) {
  if (!plain) return '';
  if (/^[a-f0-9]{64}$/i.test(plain)) return plain;
  return crypto.createHash('sha256').update(plain).digest('hex');
}
function isHashed(pw) { return /^[a-f0-9]{64}$/i.test(pw); }

const DEFAULT_PLAINTEXT = new Set(['admin123','rachelle123','auction123']);

// ── API: Auth ─────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const users  = dbGet('users', []);
  const hashed = hashPassword(password);
  const user   = users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() &&
    u.active &&
    (u.password === hashed || (!isHashed(u.password) && u.password === password))
  );

  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  // Upgrade plain-text password to hash
  if (!isHashed(user.password)) {
    user.password = hashed;
    dbSet('users', users.map(u => u.id === user.id ? user : u));
  }

  const forceChange = DEFAULT_PLAINTEXT.has(password) || !!user._forcePasswordChange;
  const userId = user.id;

  // Regenerate session to avoid fixation attacks and force a clean session
  req.session.regenerate(err => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.status(500).json({ error: 'Session error — please try again' });
    }
    req.session.userId = userId;
    req.session.save(err2 => {
      if (err2) {
        console.error('Session save error:', err2);
        return res.status(500).json({ error: 'Session error — please try again' });
      }
      console.log('Login success — session saved, userId:', userId, 'sessionID:', req.sessionID);
      const { password: _pw, ...safeUser } = user;
      res.json({ user: safeUser, forcePasswordChange: forceChange });
    });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  const users = dbGet('users', []);
  const user  = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _pw, ...safeUser } = user;
  res.json(safeUser);
});

// ── API: State ────────────────────────────────────────────────────────
app.get('/api/state', requireAuth, (req, res) => {
  const state = {};
  for (const key of PERSISTENT_KEYS) state[key] = dbGet(key);
  if (state.users) state.users = state.users.map(({ password: _pw, ...u }) => u);
  res.json(state);
});

app.post('/api/state', requireAuth, (req, res) => {
  const tx = db.transaction(() => {
    for (const key of PERSISTENT_KEYS) {
      if (!(key in req.body)) continue;
      if (key === 'users') {
        const existing = dbGet('users', []);
        const incoming = req.body.users || [];
        const merged = incoming.map(inUser => {
          const ex = existing.find(e => e.id === inUser.id);
          return { ...inUser, password: ex ? ex.password : hashPassword('changeme') };
        });
        existing.forEach(ex => { if (!merged.find(m => m.id === ex.id)) merged.push(ex); });
        dbSet('users', merged);
      } else {
        dbSet(key, req.body[key]);
      }
    }
  });
  tx();
  res.json({ ok: true });
});

// ── API: Users ────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const users = dbGet('users', []);
  res.json(users.map(({ password: _pw, ...u }) => u));
});

app.post('/api/users', requireRole('owner','operations'), (req, res) => {
  const users = dbGet('users', []);
  const data  = req.body;
  if (!data.name || !data.email) return res.status(400).json({ error: 'Name and email required' });
  if (!data.password) return res.status(400).json({ error: 'Password required' });
  const newUser = { ...data, id: 'u' + Date.now(), password: hashPassword(data.password) };
  dbSet('users', [...users, newUser]);
  const { password: _pw, ...safe } = newUser;
  res.json(safe);
});

app.put('/api/users/:id', requireRole('owner','operations'), (req, res) => {
  const users  = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner')
    return res.status(403).json({ error: 'Cannot edit Owner accounts' });
  const data = { ...target, ...req.body };
  data.password = (req.body.password && req.body.password.length >= 8)
    ? hashPassword(req.body.password)
    : target.password;
  dbSet('users', users.map(u => u.id === req.params.id ? data : u));
  const { password: _pw, ...safe } = data;
  res.json(safe);
});

app.delete('/api/users/:id', requireRole('owner'), (req, res) => {
  if (req.params.id === req.session.userId)
    return res.status(400).json({ error: 'Cannot delete your own account' });
  const users = dbGet('users', []);
  dbSet('users', users.filter(u => u.id !== req.params.id));
  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', requireRole('owner','operations'), (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const users  = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner')
    return res.status(403).json({ error: 'Cannot reset Owner passwords' });
  dbSet('users', users.map(u =>
    u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: true } : u
  ));
  res.json({ ok: true });
});

app.post('/api/users/:id/change-password', requireAuth, (req, res) => {
  const isSelf  = req.session.userId === req.params.id;
  const users   = dbGet('users', []);
  const reqUser = users.find(u => u.id === req.session.userId);
  if (!isSelf && !['owner','operations'].includes(reqUser?.role))
    return res.status(403).json({ error: 'Insufficient permissions' });
  const { password } = req.body;
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  dbSet('users', users.map(u =>
    u.id === req.params.id ? { ...u, password: hashPassword(password), _forcePasswordChange: false } : u
  ));
  res.json({ ok: true });
});

// ── API: Session check (for debugging) ───────────────────────────────
app.get('/api/session-check', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    hasSession: !!req.session,
    userId: req.session?.userId || null,
    cookiePresent: !!req.headers.cookie,
    authenticated: !!(req.session && req.session.userId)
  });
});

// ── API: Health ───────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const txns = dbGet('transactions',[]);
  const contacts = dbGet('contacts',[]);
  // Include a content hash so frontend can detect any change
  const lastTxn = txns.length ? txns[txns.length-1].id : '0';
  const lastContact = contacts.length ? contacts[contacts.length-1].id : '0';
  res.json({
    status: 'ok',
    transactions: txns.length,
    contacts: contacts.length,
    fingerprint: txns.length + '-' + contacts.length + '-' + lastTxn + '-' + lastContact,
    uptime: Math.round(process.uptime()),
    sessionStore: 'file'
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Transaction Rocket running on port ${PORT}`);
  console.log(`   DB: ${DB_PATH}`);
  console.log(`   Session store: memory (reliable, fine for small teams)`);
  console.log(`   Env: ${IS_PROD ? 'production' : 'development'}`);
});
