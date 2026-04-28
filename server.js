/**
 * SOULHASH v2 - Backend Seguro
 * SoulHash gerado imediatamente ao conectar a wallet Solana
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const crypto = require('crypto');

const app = express();

// ========================================================
// CONFIG
// ========================================================
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,        // 5 minutos
  SESSION_TTL_MS: 24 * 60 * 60 * 1000, // 24 horas
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',

  HMAC_SECRET: process.env.HMAC_SECRET || (() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('HMAC_SECRET must be set in production!');
    }
    console.warn('⚠️ Usando HMAC_SECRET temporário (apenas desenvolvimento)');
    return crypto.randomBytes(64).toString('hex');
  })(),
};

// ========================================================
// DB em memória (substituir por PostgreSQL + Redis em produção)
// ========================================================
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
};

// ========================================================
// MIDDLEWARES
// ========================================================
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente mais tarde.' }
}));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Muitas tentativas de autenticação.' }
});

const previewLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Muitas consultas de preview.' }
});

// ========================================================
// UTILS
// ========================================================

function isValidSolanaAddress(addr) {
  if (typeof addr !== 'string' || addr.length < 32 || addr.length > 44) return false;
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
  const fullHex = hmac.digest('hex');

  const CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let suffix = '';
  for (let i = 0; i < 8; i++) {
    suffix += CHARS[parseInt(fullHex.slice(i * 2, i * 2 + 2), 16) % CHARS.length];
  }

  return `\( {prefix}- \){suffix.slice(0, 4)}-${suffix.slice(4)}`;
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

function verifySignature(wallet, message, signatureB58) {
  try {
    const pub = bs58.decode(wallet);
    const msg = new TextEncoder().encode(message);
    const sig = bs58.decode(signatureB58);
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch {
    return false;
  }
}

function deriveAttrs(soulhash) {
  const h = crypto.createHash('sha256').update(soulhash).digest('hex');
  const vals = [0, 4, 8, 12, 16].map(i => parseInt(h.slice(i, i + 4), 16));
  const raw = vals.map(v => 15 + (v % 36));
  const sum = raw.reduce((a, b) => a + b, 0);
  const n = raw.map(v => Math.round(v / sum * 180));

  return { luz: n[0], sombra: n[1], equilibrio: n[2], caos: n[3], empatia: n[4] };
}

function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || token.length < 80) {
    return res.status(401).json({ error: 'Sessão ausente.' });
  }

  const s = db.sessions.get(token);
  if (!s) return res.status(401).json({ error: 'Sessão inválida.' });
  if (Date.now() > s.expiresAt) {
    db.sessions.delete(token);
    return res.status(401).json({ error: 'Sessão expirada.' });
  }

  req.wallet = s.wallet;
  next();
}

// ========================================================
// ROTAS
// ========================================================

app.get('/preview-hash', previewLimiter, (req, res) => {
  const { wallet } = req.query;
  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida.' });
  }

  res.json({
    soulhash: generateSoulHash(wallet),
    wallet_display: wallet.slice(0, 6) + '...' + wallet.slice(-4),
    preview: true
  });
});

app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;
  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida.' });
  }

  const nonce = generateNonce();
  const issuedAt = new Date();
  const soulhash = generateSoulHash(wallet);

  db.nonces.set(wallet, {
    nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: Date.now() + CONFIG.NONCE_TTL_MS
  });

  const message = [
    `${CONFIG.APP_DOMAIN} - Autenticação SoulHash`,
    '',
    `Wallet:   ${wallet}`,
    `SoulHash: ${soulhash}`,
    `Nonce:    ${nonce}`,
    `Emitido:  ${issuedAt.toISOString()}`,
    `Expira:   5 minutos`,
    '',
    `Ao assinar você confirma ser o dono desta wallet`,
    `e aceita vincular este SoulHash à sua identidade.`,
    `Nenhuma transação será realizada.`
  ].join('\n');

  res.json({ nonce, message, soulhash });
});

// ... (as rotas /login, /me, /spin, /choice permanecem iguais, só limpei o código)

app.listen(CONFIG.PORT, () => {
  console.log(`🚀 SoulHash v2 rodando na porta ${CONFIG.PORT}`);
});



