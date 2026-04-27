require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const crypto = require('crypto');

const app = express();

// ================= CONFIG =================
const CONFIG = {
  PORT: process.env.PORT || 3000,
  NONCE_TTL_MS: 5 * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
};

// ================= DATABASE =================
const db = {
  nonces: new Map(),
  sessions: new Map(),
  souls: new Map(),
  usedNonces: new Set(),
  payments: new Map() // 🚀 preparado pra txHash + wallet
};

// ================= MIDDLEWARE =================
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

// ================= UTILS =================
function isValidSolanaAddress(addr) {
  try {
    return bs58.decode(addr).length === 32;
  } catch {
    return false;
  }
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

// 🔥 ID ÚNICO (wallet + txHash)
function generateUniqueId(wallet, txHash) {
  return crypto
    .createHash('sha256')
    .update(wallet + txHash)
    .digest('hex');
}

// ================= SESSION =================
function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = db.sessions.get(token);

  if (!session || Date.now() > session.expiresAt) {
    return res.status(401).json({ error: 'Sessão inválida' });
  }

  req.wallet = session.wallet;
  next();
}

// ================= CLEANUP AUTOMÁTICO =================
setInterval(() => {
  const now = Date.now();

  for (const [wallet, data] of db.nonces.entries()) {
    if (data.expiresAt < now) db.nonces.delete(wallet);
  }

  for (const [token, session] of db.sessions.entries()) {
    if (session.expiresAt < now) db.sessions.delete(token);
  }

}, 60 * 1000);

// ================= ROTAS =================

// 🔐 NONCE
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const nonce = generateNonce();

  db.nonces.set(wallet, {
    nonce,
    expiresAt: Date.now() + CONFIG.NONCE_TTL_MS
  });

  const message = `Login SoulHash\nWallet: ${wallet}\nNonce: ${nonce}`;

  res.json({ nonce, message });
});

// 🔑 LOGIN
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  if (!wallet || !signature || !nonce) {
    return res.status(400).json({ error: 'Dados inválidos' });
  }

  const nonceData = db.nonces.get(wallet);

  if (!nonceData || nonceData.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce inválido' });
  }

  // 🚨 evita replay attack
  if (db.usedNonces.has(nonce)) {
    return res.status(401).json({ error: 'Nonce já usado' });
  }

  const message = `Login SoulHash\nWallet: ${wallet}\nNonce: ${nonce}`;

  if (!verifySignature(wallet, message, signature)) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  const token = generateSessionToken();

  db.sessions.set(token, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS
  });

  // cria jogador
  if (!db.souls.has(wallet)) {
    db.souls.set(wallet, {
      wallet,
      coins: 100,
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

    return res.json({ result: 'win', coins: soul.coins, grid });
  }

  grid = Array.from({ length: 3 }, () =>
    Array.from({ length: 3 }, rand)
  );

  res.json({ result: 'lose', coins: soul.coins, grid });
});

// 👤 ME
app.get('/me', requireSession, (req, res) => {
  res.json(db.souls.get(req.wallet));
});

// ================= FUTURO: PAGAMENTO =================
// exemplo preparado
app.post('/payment', requireSession, (req, res) => {
  const { txHash } = req.body;

  if (!txHash) {
    return res.status(400).json({ error: 'txHash obrigatório' });
  }

  const id = generateUniqueId(req.wallet, txHash);

  if (db.payments.has(id)) {
    return res.status(400).json({ error: 'Pagamento já registrado' });
  }

  db.payments.set(id, {
    wallet: req.wallet,
    txHash,
    createdAt: Date.now()
  });

  res.json({ success: true, id });
});

// ================= START =================
app.listen(CONFIG.PORT, () => {
  console.log('🔥 SoulHash rodando na porta ' + CONFIG.PORT);
});

