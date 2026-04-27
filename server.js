/**
 * SOULHASH v2 — Backend Seguro (REFATORADO)
 */

require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const nacl      = require('tweetnacl');
const bs58      = require('bs58');
const crypto    = require('crypto');

const app = express();

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',
  HMAC_SECRET: process.env.HMAC_SECRET || crypto.randomBytes(64).toString('hex'),
};

// ─────────────────────────────────────────────
// DB (memória)
// ─────────────────────────────────────────────
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
};

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150
}));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10
});

const previewLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30
});

// ─────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────
function isValidSolanaAddress(addr) {
  if (typeof addr !== 'string') return false;
  try {
    return bs58.decode(addr).length === 32;
  } catch {
    return false;
  }
}

// SoulHash determinístico
function generateSoulHash(wallet) {
  const prefix = wallet.slice(0, 6).toUpperCase();

  const hmac = crypto.createHmac('sha256', CONFIG.HMAC_SECRET);
  hmac.update('SOULHASH_V2:' + wallet);
  const hex = hmac.digest('hex');

  const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ';

  let out = '';
  for (let i = 0; i < 8; i++) {
    out += chars[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % chars.length];
  }

  return `${prefix}-${out.slice(0,4)}-${out.slice(4,8)}`;
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSession() {
  return crypto.randomBytes(48).toString('hex');
}

function verifySignature(wallet, message, signature) {
  try {
    const pubKey = bs58.decode(wallet);
    const msg = new TextEncoder().encode(message);
    const sig = bs58.decode(signature);

    return nacl.sign.detached.verify(msg, sig, pubKey);
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// PREVIEW HASH
app.get('/preview-hash', previewLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  return res.json({
    soulhash: generateSoulHash(wallet),
    wallet_display: wallet.slice(0,6) + '...' + wallet.slice(-4)
  });
});

// NONCE
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const nonce = generateNonce();
  const soulhash = generateSoulHash(wallet);

  db.nonces.set(wallet, {
    nonce,
    expiresAt: Date.now() + CONFIG.NONCE_TTL_MS
  });

  const message =
`SoulHash Authentication

Wallet: ${wallet}
SoulHash: ${soulhash}
Nonce: ${nonce}

Assine para confirmar identidade.`;

  return res.json({
    nonce,
    message,
    soulhash
  });
});

// LOGIN
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  if (!signature || !nonce) {
    return res.status(400).json({ error: 'Dados inválidos' });
  }

  if (db.usedNonces.has(nonce)) {
    return res.status(401).json({ error: 'Nonce já usado' });
  }

  const stored = db.nonces.get(wallet);

  if (!stored || stored.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce inválido' });
  }

  if (Date.now() > stored.expiresAt) {
    db.nonces.delete(wallet);
    return res.status(401).json({ error: 'Nonce expirado' });
  }

  const soulhash = generateSoulHash(wallet);

  const message =
`SoulHash Authentication

Wallet: ${wallet}
SoulHash: ${soulhash}
Nonce: ${nonce}

Assine para confirmar identidade.`;

  if (!verifySignature(wallet, message, signature)) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  const sessionToken = generateSession();

  db.sessions.set(sessionToken, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS
  });

  if (!db.souls.has(wallet)) {
    db.souls.set(wallet, {
      soulhash,
      wallet_display: wallet.slice(0,6) + '...' + wallet.slice(-4),
      createdAt: new Date().toISOString(),
      hash_balance: 100,
      energy: 7,
      maxEnergy: 10,
      level: 1,
      stats: { xp: 0 },
      ownedCards: {},
      dimProgress: 0
    });
  }

  const soul = db.souls.get(wallet);

  const { wallet: _w, ...safe } = soul;

  return res.json({
    sessionToken,
    ...safe
  });
});

// SESSION CHECK
function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];

  if (!token) return res.status(401).json({ error: 'Sem sessão' });

  const session = db.sessions.get(token);

  if (!session) return res.status(401).json({ error: 'Sessão inválida' });

  if (Date.now() > session.expiresAt) {
    db.sessions.delete(token);
    return res.status(401).json({ error: 'Sessão expirada' });
  }

  req.wallet = session.wallet;
  next();
}

// ME
app.get('/me', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);
  if (!soul) return res.status(404).json({ error: 'Não encontrado' });

  const { wallet: _w, ...safe } = soul;
  res.json(safe);
});

// SPIN (simplificado e estável)
app.post('/spin', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);

  if (!soul) return res.status(404).json({ error: 'Sem alma' });
  if (soul.energy <= 0) return res.status(400).json({ error: 'Sem energia' });

  soul.energy--;

  const win = Math.random() < 0.3;

  const grid = Array(9).fill(null).map(() =>
    ['luz','sombra','caos','empatia','equil'][Math.floor(Math.random()*5)]
  );

  let reward = 0;

  if (win) {
    reward = 50;
    soul.hash_balance += reward;
    soul.stats.xp += 30;
  } else {
    soul.stats.xp += 10;
  }

  soul.level = Math.floor(soul.stats.xp / 1000) + 1;

  db.souls.set(req.wallet, soul);

  res.json({
    result: {
      isWin: win,
      grid,
      reward
    },
    hash_balance: soul.hash_balance,
    energy: soul.energy,
    maxEnergy: soul.maxEnergy,
    stats: soul.stats,
    level: soul.level,
    ownedCards: soul.ownedCards,
    dimProgress: soul.dimProgress
  });
});

// ─────────────────────────────────────────────
app.listen(CONFIG.PORT, () => {
  console.log(`SoulHash running on port ${CONFIG.PORT}`);
});


