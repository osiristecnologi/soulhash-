/**
 * SOULHASH — Backend Web3 (PHANTOM / SOLANA)
 * Autenticação via assinatura Solana (Phantom Wallet)
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const bs58 = require('bs58');
const { PublicKey } = require('@solana/web3.js');

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// STORAGE
// ─────────────────────────────
const nonceStore = new Map();
const soulhashStore = new Map();

// ─────────────────────────────
// RATE LIMIT SIMPLES
// ─────────────────────────────
const ipRequests = new Map();

function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = ipRequests.get(ip);

  if (!entry || now > entry.resetAt) {
    ipRequests.set(ip, { count: 1, resetAt: now + 60_000 });
    return next();
  }

  if (entry.count >= 5) {
    return res.status(429).json({
      error: 'Muitas requisições. Aguarde 1 minuto.',
    });
  }

  entry.count++;
  next();
}

// limpeza
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipRequests) {
    if (now > entry.resetAt) ipRequests.delete(ip);
  }
  for (const [wallet, data] of nonceStore) {
    if (now > data.expiresAt) nonceStore.delete(wallet);
  }
}, 5 * 60_000);

// ─────────────────────────────
// MIDDLEWARE
// ─────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*'}));
app.use(express.json({ limit: '10kb' }));

// ─────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────

function isValidSolanaAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function buildMessage(nonce) {
  return `Login SoulHash (Solana) - nonce: ${nonce}`;
}

function generateSoulHash(wallet) {
  const hash = crypto
    .createHash('sha256')
    .update(wallet.toLowerCase() + 'SOULHASH-SOLANA')
    .digest('hex');

  return hash.slice(0, 24).toUpperCase();
}

// ─────────────────────────────
// VERIFY PHANTOM SIGNATURE
// ─────────────────────────────
function verifySignatureSolana(publicKey, message, signature) {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signature);
    const publicKeyBytes = bs58.decode(publicKey);

    return nacl.sign.detached.verify(
      messageBytes,
      signatureBytes,
      publicKeyBytes
    );
  } catch {
    return false;
  }
}

// ─────────────────────────────
// DERIVADOR DE ATRIBUTOS
// ─────────────────────────────
function deriveAttr(soulhash, index) {
  const hash = crypto.createHash('sha256').update(soulhash).digest('hex');
  const vals = [0, 4, 8, 12, 16].map(i => parseInt(hash.slice(i, i + 4), 16));
  const raw = vals.map(v => 15 + (v % 36));
  const sum = raw.reduce((a, b) => a + b, 0);
  return Math.round((raw[index] / sum) * 180);
}

// ─────────────────────────────
// ROTAS
// ─────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'online', chain: 'solana' });
});

/**
 * CHALLENGE
 */
app.post('/challenge', rateLimit, (req, res) => {
  const { wallet } = req.body;

  if (!wallet || !isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet Solana inválida' });
  }

  const nonce = generateNonce();
  const message = buildMessage(nonce);

  nonceStore.set(wallet, {
    nonce,
    message,
    expiresAt: Date.now() + 5 * 60_000,
  });

  res.json({ message, nonce });
});

/**
 * VERIFY PHANTOM
 */
app.post('/verify', rateLimit, (req, res) => {
  const { wallet, signature, message } = req.body;

  if (!wallet || !signature || !message) {
    return res.status(400).json({ error: 'Campos obrigatórios' });
  }

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  const stored = nonceStore.get(wallet);

  if (!stored) {
    return res.status(401).json({ error: 'Nonce não encontrado' });
  }

  if (stored.message !== message) {
    return res.status(401).json({ error: 'Mensagem inválida' });
  }

  const valid = verifySignatureSolana(wallet, message, signature);

  if (!valid) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  nonceStore.delete(wallet);

  let isNew = !soulhashStore.has(wallet);

  if (isNew) {
    soulhashStore.set(wallet, generateSoulHash(wallet));
  }

  const soulhash = soulhashStore.get(wallet);

  res.json({
    ok: true,
    wallet,
    soulhash,
    isNew,
    message: isNew
      ? 'SoulHash criado via Phantom'
      : 'SoulHash recuperado'
  });
});

/**
 * LOGIN SIMPLES
 */
app.post('/login', rateLimit, (req, res) => {
  const { wallet } = req.body;

  if (!wallet || !isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida' });
  }

  if (!soulhashStore.has(wallet)) {
    soulhashStore.set(wallet, generateSoulHash(wallet));
  }

  const soulhash = soulhashStore.get(wallet);

  res.json({
    ok: true,
    wallet,
    soulhash,
    luz: deriveAttr(soulhash, 0),
    sombra: deriveAttr(soulhash, 1),
    equilibrio: deriveAttr(soulhash, 2),
    caos: deriveAttr(soulhash, 3),
    empatia: deriveAttr(soulhash, 4),
    energy: 7,
    maxEnergy: 10,
    level: 1
  });
});

// ─────────────────────────────
// 404
// ─────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// ─────────────────────────────
// START
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`SoulHash Solana rodando na porta ${PORT}`);
});






