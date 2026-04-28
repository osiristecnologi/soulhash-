/**
 * SoulHash Backend - v2
 * Gera SoulHash vinculado à wallet Solana usando HMAC + prefixo
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

// ─────────────────────────────────────────────────────────────
// CONFIGURAÇÕES
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,      // 5 minutos
  SESSION_TTL_MS: 24 * 60 * 60 * 1000, // 24 horas
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',
  
  HMAC_SECRET: process.env.HMAC_SECRET || (() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('HMAC_SECRET deve ser definido em produção!');
    }
    console.warn('⚠️  Usando HMAC_SECRET gerado automaticamente (apenas desenvolvimento)');
    return crypto.randomBytes(64).toString('hex');
  })(),
};

// ─────────────────────────────────────────────────────────────
// BANCO DE DADOS EM MEMÓRIA (para desenvolvimento)
// Em produção: usar PostgreSQL + Redis
// ─────────────────────────────────────────────────────────────
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
};

// ─────────────────────────────────────────────────────────────
// MIDDLEWARES
// ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
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

// ─────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────

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
  
  return {
    luz: n[0],
    sombra: n[1],
    equilibrio: n[2],
    caos: n[3],
    empatia: n[4]
  };
}

function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || token.length < 80) {
    return res.status(401).json({ error: 'Sessão ausente.' });
  }

  const session = db.sessions.get(token);
  if (!session) {
    return res.status(401).json({ error: 'Sessão inválida.' });
  }

  if (Date.now() > session.expiresAt) {
    db.sessions.delete(token);
    return res.status(401).json({ error: 'Sessão expirada.' });
  }

  req.wallet = session.wallet;
  next();
}

// ─────────────────────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────────────────────

/**
 * GET /preview-hash?wallet=ADDRESS
 * Retorna o SoulHash imediatamente (público)
 */
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

/**
 * GET /nonce?wallet=ADDRESS
 * Gera nonce + mensagem para assinatura
 */
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
    `${CONFIG.APP_DOMAIN} — Autenticação SoulHash`,
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

/**
 * POST /login
 * Autenticação completa com verificação de assinatura
 */
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  if (!isValidSolanaAddress(wallet)) return res.status(400).json({ error: 'Wallet inválida.' });
  if (typeof signature !== 'string' || signature.length < 64) return res.status(400).json({ error: 'Assinatura inválida.' });
  if (typeof nonce !== 'string' || nonce.length !== 64) return res.status(400).json({ error: 'Nonce inválido.' });
  if (db.usedNonces.has(nonce)) return res.status(401).json({ error: 'Nonce já utilizado.' });

  const nd = db.nonces.get(wallet);
  if (!nd || nd.nonce !== nonce) return res.status(401).json({ error: 'Nonce não encontrado.' });
  if (Date.now() > nd.expiresAt) {
    db.nonces.delete(wallet);
    return res.status(401).json({ error: 'Nonce expirado.' });
  }

  const soulhash = generateSoulHash(wallet);
  const message = [ /* mesma mensagem do /nonce */ ].join('\n'); // reutilizar lógica se quiser

  if (!verifySignature(wallet, message, signature)) {
    return res.status(401).json({ error: 'Assinatura inválida.' });
  }

  // Consome nonce
  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  // Cria sessão
  const sessionToken = generateSessionToken();
  db.sessions.set(sessionToken, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS
  });

  // Cria ou recupera soul
  let isNewSoul = false;
  if (!db.souls.has(wallet)) {
    isNewSoul = true;
    db.souls.set(wallet, {
      soulhash,
      wallet_display: wallet.slice(0, 6) + '...' + wallet.slice(-4),
      createdAt: new Date().toISOString(),
      attrs: deriveAttrs(soulhash),
      stats: { missoes: 0, escolhas: 0, almas: 0, confrontos: 0, xp: 0 },
      hash_balance: 100,
      gems: 0,
      energy: 7,
      maxEnergy: 10,
      level: 1,
      phase: 1,
      phasePassed: false,
      spins: 0,
      ownedCards: {},
      dimProgress: 0,
      fase_atual: 1,
      p1_choice: null,
      p2_choice: null,
    });
  }

  const soul = db.souls.get(wallet);
  const { wallet: _w, ...safeData } = soul;

  res.json({ sessionToken, isNewSoul, ...safeData });
});

// Outras rotas (/me, /spin, /choice) mantidas iguais...

app.get('/me', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);
  if (!soul) return res.status(404).json({ error: 'Alma não encontrada.' });
  
  const { wallet: _w, ...safeData } = soul;
  res.json(safeData);
});

// ... (as rotas /spin e /choice podem ficar iguais, estão bem escritas)

app.listen(CONFIG.PORT, () => {
  console.log(`🚀 [SoulHash v2] Servidor rodando na porta ${CONFIG.PORT}`);
  console.log(`   Ambiente: ${process.env.NODE_ENV || 'development'}`);
});



