require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const crypto = require('crypto');

const app = express();

// ─────────────────────────────
// CONFIG
// ─────────────────────────────
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',
};

// ─────────────────────────────
// MEMORY STORE
// ─────────────────────────────
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
};

// ─────────────────────────────
// MIDDLEWARE
// ─────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10kb' }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
}));

// ─────────────────────────────
// HEALTH CHECK (RESOLVE "Cannot GET /")
// ─────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SoulHash API',
    version: 'v2'
  });
});

// ─────────────────────────────
// UTILS
// ─────────────────────────────
function isValidWallet(addr) {
  return typeof addr === 'string' && addr.length >= 32 && addr.length <= 44;
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

// SoulHash FIXO por wallet
function generateSoulHash(wallet) {
  const prefix = wallet.slice(0, 6).toUpperCase();
  const hash = crypto
    .createHash('sha256')
    .update(wallet + 'SOULHASH_V2')
    .digest('hex');

  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  let suffix = '';
  for (let i = 0; i < 8; i++) {
    suffix += chars[parseInt(hash[i * 2], 16) % chars.length];
  }

  return `${prefix}-${suffix.slice(0, 4)}-${suffix.slice(4)}`;
}

// ─────────────────────────────
// ROUTES
// ─────────────────────────────

// 1. CHALLENGE
app.get('/challenge', (req, res) => {
  const { wallet } = req.query;

  if (!isValidWallet(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const nonce = generateNonce();

  db.nonces.set(wallet, {
    nonce,
    expires: Date.now() + CONFIG.NONCE_TTL_MS,
  });

  const message = `Login SoulHash\nWallet: ${wallet}\nNonce: ${nonce}`;

  res.json({ nonce, message });
});

// 2. LOGIN (simplificado sem assinatura real ainda)
app.post('/login', (req, res) => {
  const { wallet, nonce } = req.body;

  if (!isValidWallet(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const stored = db.nonces.get(wallet);

  if (!stored || stored.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce inválido' });
  }

  if (Date.now() > stored.expires) {
    return res.status(401).json({ error: 'Nonce expirado' });
  }

  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  const sessionToken = generateSessionToken();

  db.sessions.set(sessionToken, {
    wallet,
    expires: Date.now() + CONFIG.SESSION_TTL_MS,
  });

  let soul = db.souls.get(wallet);

  if (!soul) {
    soul = {
      wallet,
      soulhash: generateSoulHash(wallet),
      createdAt: new Date().toISOString(),
      energy: 10,
      level: 1,
    };

    db.souls.set(wallet, soul);
  }

  res.json({
    sessionToken,
    soul,
  });
});

// 3. ME
app.get('/me', (req, res) => {
  const token = req.headers['x-session-token'];

  const session = db.sessions.get(token);

  if (!session) {
    return res.status(401).json({ error: 'Sessão inválida' });
  }

  const soul = db.souls.get(session.wallet);

  res.json(soul);
});

// ─────────────────────────────
// START SERVER
// ─────────────────────────────
app.listen(CONFIG.PORT, () => {
  console.log(`SoulHash rodando na porta ${CONFIG.PORT}`);
});




