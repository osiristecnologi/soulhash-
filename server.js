/**
 * SOULHASH — Backend Seguro + SLOT 🎰
 */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const nacl       = require('tweetnacl');
const bs58       = require('bs58');
const crypto     = require('crypto');

const app = express();

// CONFIG
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  APP_DOMAIN: process.env.APP_DOMAIN || 'soulhash.app',
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
};

// DATABASE (fake)
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
};

// MIDDLEWARES
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
});

// UTILS
function isValidSolanaAddress(addr) {
  try { return bs58.decode(addr).length === 32; }
  catch { return false; }
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

function verifySignature(wallet, message, signatureB58) {
  try {
    return nacl.sign.detached.verify(
      new TextEncoder().encode(message),
      bs58.decode(signatureB58),
      bs58.decode(wallet)
    );
  } catch {
    return false;
  }
}

function generateSoulHash(wallet) {
  const h = crypto.createHmac('sha256', CONFIG.SESSION_SECRET);
  h.update(wallet);
  return h.digest('hex').slice(0, 12);
}

// SESSION
function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = db.sessions.get(token);

  if (!session || Date.now() > session.expiresAt) {
    return res.status(401).json({ error: 'Sessão inválida' });
  }

  req.wallet = session.wallet;
  next();
}

// ROTAS
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const nonce = generateNonce();
  db.nonces.set(wallet, { nonce, expiresAt: Date.now() + CONFIG.NONCE_TTL_MS });

  const message = `Login SoulHash\nWallet: ${wallet}\nNonce: ${nonce}`;

  res.json({ nonce, message });
});

app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  const nonceData = db.nonces.get(wallet);
  if (!nonceData || nonceData.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce inválido' });
  }

  const message = `Login SoulHash\nWallet: ${wallet}\nNonce: ${nonce}`;

  if (!verifySignature(wallet, message, signature)) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  const token = generateSessionToken();

  db.sessions.set(token, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS
  });

  // cria jogador
  if (!db.souls.has(wallet)) {
    db.souls.set(wallet, {
      wallet,
      coins: 100, // 🎁 BONUS INICIAL
      xp: 0
    });
  }

  res.json({ sessionToken: token });
});

// 🎰 SLOT
app.post('/spin', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);

  const COST = 10;

  if (soul.coins < COST) {
    return res.status(400).json({ error: 'Sem moedas' });
  }

  soul.coins -= COST;

  const win = Math.random() <= 0.3;

  const cards = ['luz', 'sombra', 'caos', 'equilibrio', 'empatia'];

  const rand = () => cards[Math.floor(Math.random() * cards.length)];

  let grid;

  if (win) {
    const c = rand();
    grid = [
      [c, c, c],
      [rand(), rand(), rand()],
      [rand(), rand(), rand()]
    ];

    soul.coins += 25;

    return res.json({
      result: 'win',
      coins: soul.coins,
      grid
    });
  }

  grid = [
    [rand(), rand(), rand()],
    [rand(), rand(), rand()],
    [rand(), rand(), rand()]
  ];

  res.json({
    result: 'lose',
    coins: soul.coins,
    grid
  });
});

// ME
app.get('/me', requireSession, (req, res) => {
  res.json(db.souls.get(req.wallet));
});

// START
app.listen(CONFIG.PORT, () => {
  console.log('🔥 SoulHash rodando na porta ' + CONFIG.PORT);
});

