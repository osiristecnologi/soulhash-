/**
 * SOULHASH v2 — Backend Seguro (REFATORADO)
 */

require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const nacl      = require('tweetnacl');
const crypto    = require('crypto');

// FIX CRÍTICO: bs58 import seguro
const bs58 = require('bs58').default || require('bs58');

const app = express();

// ─────────────────────────────────────────────
// CONFIG SEGURA
// ─────────────────────────────────────────────
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',
  HMAC_SECRET:
    process.env.HMAC_SECRET ||
    crypto.randomBytes(64).toString('hex'),
};

// ─────────────────────────────────────────────
// DB EM MEMÓRIA
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
  max: 150,
}));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
});

// ─────────────────────────────────────────────
// HEALTH CHECK (IMPORTANTE PRA DEBUG)
// ─────────────────────────────────────────────
app.get('/health', (_, res) => {
  res.json({ ok: true, status: 'SoulHash API running' });
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

function generateSoulHash(wallet) {
  const prefix = wallet.slice(0, 6).toUpperCase();

  const hmac = crypto.createHmac('sha256', CONFIG.HMAC_SECRET);
  hmac.update('SOULHASH_V2:' + wallet);

  const hex = hmac.digest('hex');

  const CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let out = '';

  for (let i = 0; i < 8; i++) {
    out += CHARS[parseInt(hex.slice(i * 2, i * 2 + 2), 16) % CHARS.length];
  }

  return `${prefix}-${out.slice(0, 4)}-${out.slice(4)}`;
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSessionToken() {
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
// ROTAS
// ─────────────────────────────────────────────

// preview
app.get('/preview-hash', (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  return res.json({
    soulhash: generateSoulHash(wallet),
    wallet_display: wallet.slice(0, 6) + '...' + wallet.slice(-4),
  });
});

// nonce
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const nonce = generateNonce();

  db.nonces.set(wallet, {
    nonce,
    expiresAt: Date.now() + CONFIG.NONCE_TTL_MS,
  });

  const message = `SoulHash login\nwallet:${wallet}\nnonce:${nonce}`;

  res.json({ nonce, message });
});

// login
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  if (db.usedNonces.has(nonce)) {
    return res.status(401).json({ error: 'Nonce já usado' });
  }

  const data = db.nonces.get(wallet);

  if (!data || data.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce inválido' });
  }

  if (Date.now() > data.expiresAt) {
    return res.status(401).json({ error: 'Nonce expirado' });
  }

  const message = `SoulHash login\nwallet:${wallet}\nnonce:${nonce}`;

  if (!verifySignature(wallet, message, signature)) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  db.usedNonces.add(nonce);

  const sessionToken = generateSessionToken();

  db.sessions.set(sessionToken, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS,
  });

  const soulhash = generateSoulHash(wallet);

  if (!db.souls.has(wallet)) {
    db.souls.set(wallet, {
      soulhash,
      createdAt: new Date().toISOString(),
      energy: 10,
      level: 1,
      xp: 0,
    });
  }

  return res.json({
    sessionToken,
    soulhash,
  });
});

// me
app.get('/me', (req, res) => {
  const token = req.headers['x-session-token'];

  const session = db.sessions.get(token);

  if (!session) {
    return res.status(401).json({ error: 'Sessão inválida' });
  }

  const soul = db.souls.get(session.wallet);

  return res.json(soul);
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
app.listen(CONFIG.PORT, () => {
  console.log(`🚀 SoulHash API rodando na porta ${CONFIG.PORT}`);
});


