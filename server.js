'use strict';
const express    = require('express');
const session    = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database   = require('better-sqlite3');
const path       = require('path');
const crypto     = require('crypto');
const fs         = require('fs');

// ── Config ────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const DATA_DIR    = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_PATH     = path.join(DATA_DIR, 'rocket.db');
const SESS_SECRET = process.env.SESSION_SECRET || 'change-me-in-production-' + crypto.randomBytes(16).toString('hex');
const IS_PROD     = process.env.NODE_ENV === 'production';

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Database setup ────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Single table: key-value store for each data domain
// This mirrors the localStorage approach — clean migration
db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid    TEXT PRIMARY KEY,
    sess   TEXT NOT NULL,
    expired TEXT NOT NULL
  );
`);

// ── DB helpers ────────────────────────────────────────────────────────
const stmtGet    = db.prepare('SELECT value FROM store WHERE key = ?');
const stmtSet    = db.prepare('INSERT OR REPLACE INTO store (key, value, updated_at) VALUES (?, ?, datetime(\'now\'))');
const stmtDelete = db.prepare('DELETE FROM store WHERE key = ?');

function dbGet(key, fallback = null) {
  const row = stmtGet.get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function dbSet(key, value) {
  stmtSet.run(key, JSON.stringify(value));
}

// ── Seed data (from the original HTML app) ───────────────────────────
const DEFAULT_SEED = {
  transactions: [],
  contacts: [],
  users: [
    {
      id: 'u1', name: 'Daniel Gutierrez', email: 'dxgutierrez@kw.com',
      password: 'admin123', role: 'owner', active: true, chatWebhook: '',
      perms: { dashboard:true, transactions:true, contacts:true, calendar:true,
               tasks:true, marketing:true, production:true, documents:true,
               settings:true, onboarding:true }
    },
    {
      id: 'u2', name: 'Rachelle', email: 'transactions@bidwichita.com',
      password: 'rachelle123', role: 'operations', active: true, chatWebhook: '',
      perms: { dashboard:true, transactions:true, contacts:true, calendar:true,
               tasks:true, marketing:true, production:true, documents:true,
               settings:true, onboarding:true }
    },
    {
      id: 'u3', name: 'Jesus', email: 'listings@bidwichita.com',
      password: 'auction123', role: 'agent', active: true, chatWebhook: '',
      perms: { dashboard:true, transactions:true, contacts:true, calendar:true,
               tasks:true, marketing:false, production:false, documents:true,
               settings:false, onboarding:true }
    },
    {
      id: 'u4', name: 'Sophia', email: 'sophia@bidwichita.com',
      password: 'auction123', role: 'marketing', active: true, chatWebhook: '',
      perms: { dashboard:true, transactions:false, contacts:false, calendar:true,
               tasks:true, marketing:true, production:false, documents:false,
               settings:false, onboarding:false }
    }
  ],
  templates: {},
  phases: {},
  customEvents: [],
  documents: [],
  emailTemplates: [],
  savedViews: [],
  dailyActivity: {},
  chatSpaces: [
    { id:'cs1', name:'Team Space',     url:'', type:'team'      },
    { id:'cs2', name:'Closing Space',  url:'', type:'closing'   },
    { id:'cs3', name:'Marketing Space',url:'', type:'marketing' },
    { id:'cs4', name:'Admin Space',    url:'', type:'admin'     }
  ],
  quickLinks: [
    { id:'ql1', label:'KW Command',  url:'https://agent.kw.com',            color:'#B42318' },
    { id:'ql2', label:'Authentisign',url:'https://app.authentisign.com',     color:'#1D4ED8' },
    { id:'ql3', label:'Paragon MLS', url:'https://paragonrels.com',          color:'#027A48' },
    { id:'ql4', label:'BidWichita',  url:'https://bidwichita.com',           color:'#7C3AED' }
  ],
  onboardingItems: null,
  teamChatWebhook: '',
  agentView: 'Daniel Gutierrez'
};

// Initialize DB with seed data if first run
const PERSISTENT_KEYS = [
  'transactions','contacts','users','templates','phases',
  'customEvents','documents','emailTemplates','savedViews',
  'dailyActivity','chatSpaces','quickLinks','onboardingItems',
  'teamChatWebhook','agentView'
];

for (const key of PERSISTENT_KEYS) {
  if (!stmtGet.get(key)) {
    dbSet(key, DEFAULT_SEED[key] ?? null);
  }
}

// ── Express setup ─────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '50mb' }));       // large for PDF uploads
app.use(express.urlencoded({ extended: true }));

// Sessions stored in SQLite (same DB file, different table)
app.use(session({
  store: new SQLiteStore({
    db: 'rocket.db',
    dir: DATA_DIR,
    table: 'sessions'
  }),
  secret: SESS_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: IS_PROD,        // HTTPS only in production
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000  // 7 days
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
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

// ── Password hashing (SHA-256, same as frontend) ─────────────────────
function hashPassword(plain) {
  if (!plain) return '';
  // If already hashed (64 hex chars), return as-is
  if (/^[a-f0-9]{64}$/i.test(plain)) return plain;
  return crypto.createHash('sha256').update(plain).digest('hex');
}

function isHashed(pw) {
  return /^[a-f0-9]{64}$/i.test(pw);
}

// Default passwords that must be changed on first login
const DEFAULT_PLAINTEXT = new Set(['admin123', 'rachelle123', 'auction123']);
function isDefaultPassword(plain) {
  return DEFAULT_PLAINTEXT.has(plain);
}

// ── API: Auth ─────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const users = dbGet('users', []);
  const hashed = hashPassword(password);

  const user = users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() &&
    u.active &&
    (u.password === hashed || (!isHashed(u.password) && u.password === password))
  );

  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  // Auto-upgrade plain-text password to hash
  if (!isHashed(user.password)) {
    user.password = hashed;
    const updatedUsers = users.map(u => u.id === user.id ? user : u);
    dbSet('users', updatedUsers);
  }

  // Flag if using default password
  const forceChange = isDefaultPassword(password) || user._forcePasswordChange;

  req.session.userId = user.id;
  req.session.save();

  // Return user without password
  const { password: _pw, ...safeUser } = user;
  res.json({ user: safeUser, forcePasswordChange: forceChange });
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

// ── API: State (main data sync) ───────────────────────────────────────
// GET all persistent state — called on app load
app.get('/api/state', requireAuth, (req, res) => {
  const state = {};
  for (const key of PERSISTENT_KEYS) {
    state[key] = dbGet(key);
  }
  // Strip passwords from users
  if (state.users) {
    state.users = state.users.map(({ password: _pw, ...u }) => u);
  }
  res.json(state);
});

// POST full state — called by saveState()
app.post('/api/state', requireAuth, (req, res) => {
  const { body } = req;
  const db_tx = db.transaction(() => {
    for (const key of PERSISTENT_KEYS) {
      if (key in body) {
        // Never let client overwrite passwords via state sync
        if (key === 'users') {
          const existing = dbGet('users', []);
          const incoming = body.users || [];
          // Merge: keep existing passwords, update everything else
          const merged = incoming.map(inUser => {
            const ex = existing.find(e => e.id === inUser.id);
            return { ...inUser, password: ex ? ex.password : hashPassword('changeme') };
          });
          // Also include any users in DB not in incoming (safety)
          existing.forEach(ex => {
            if (!merged.find(m => m.id === ex.id)) merged.push(ex);
          });
          dbSet('users', merged);
        } else {
          dbSet(key, body[key]);
        }
      }
    }
  });
  db_tx();
  res.json({ ok: true });
});

// ── API: Users (password-sensitive operations) ────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const users = dbGet('users', []);
  res.json(users.map(({ password: _pw, ...u }) => u));
});

app.post('/api/users', requireRole('owner', 'operations'), (req, res) => {
  const users = dbGet('users', []);
  const data  = req.body;
  if (!data.name || !data.email) return res.status(400).json({ error: 'Name and email required' });
  if (!data.password) return res.status(400).json({ error: 'Password required' });
  const hashed = hashPassword(data.password);
  const newUser = { ...data, id: 'u' + Date.now(), password: hashed };
  dbSet('users', [...users, newUser]);
  const { password: _pw, ...safe } = newUser;
  res.json(safe);
});

app.put('/api/users/:id', requireRole('owner', 'operations'), (req, res) => {
  const users   = dbGet('users', []);
  const target  = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });

  // Operations cannot edit Owners (only Owner can)
  if (req.user.role === 'operations' && target.role === 'owner') {
    return res.status(403).json({ error: 'Cannot edit Owner accounts' });
  }

  const data = { ...target, ...req.body };
  // Handle password change
  if (req.body.password && req.body.password.length >= 8) {
    data.password = hashPassword(req.body.password);
  } else {
    data.password = target.password; // keep existing
  }

  const updated = users.map(u => u.id === req.params.id ? data : u);
  dbSet('users', updated);
  const { password: _pw, ...safe } = data;
  res.json(safe);
});

app.delete('/api/users/:id', requireRole('owner'), (req, res) => {
  if (req.params.id === req.session.userId) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  const users = dbGet('users', []);
  dbSet('users', users.filter(u => u.id !== req.params.id));
  res.json({ ok: true });
});

app.post('/api/users/:id/reset-password', requireRole('owner', 'operations'), (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const users  = dbGet('users', []);
  const target = users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (req.user.role === 'operations' && target.role === 'owner') {
    return res.status(403).json({ error: 'Cannot reset Owner passwords' });
  }
  const updated = users.map(u =>
    u.id === req.params.id
      ? { ...u, password: hashPassword(password), _forcePasswordChange: true }
      : u
  );
  dbSet('users', updated);
  res.json({ ok: true });
});

app.post('/api/users/:id/change-password', requireAuth, (req, res) => {
  // Users can change their own password; owner/ops can change anyone's
  const isSelf = req.session.userId === req.params.id;
  const users  = dbGet('users', []);
  const reqUser = users.find(u => u.id === req.session.userId);

  if (!isSelf && !['owner','operations'].includes(reqUser?.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }

  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const updated = users.map(u =>
    u.id === req.params.id
      ? { ...u, password: hashPassword(password), _forcePasswordChange: false }
      : u
  );
  dbSet('users', updated);

  // Update session if changing own password
  if (isSelf) {
    const me = updated.find(u => u.id === req.params.id);
    req.session.userId = me.id;
  }

  res.json({ ok: true });
});

// ── API: Health check ─────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    db: DB_PATH,
    users: (dbGet('users', [])).length,
    transactions: (dbGet('transactions', [])).length,
    uptime: Math.round(process.uptime())
  });
});

// ── Catch-all: serve index.html for SPA routing ───────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Transaction Rocket running on port ${PORT}`);
  console.log(`   DB: ${DB_PATH}`);
  console.log(`   Env: ${IS_PROD ? 'production' : 'development'}`);
});
