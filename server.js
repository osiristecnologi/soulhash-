/**
 * SOULHASH — Backend Web3 Seguro
 * Autenticação via assinatura de wallet (EIP-191 / personal_sign)
 * ethers.js + Express + rate limit
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const crypto    = require('crypto');
const { ethers } = require('ethers');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────
// STORAGE EM MEMÓRIA
// ─────────────────────────────────────────────────────────────
const nonceStore   = new Map(); // wallet → { nonce, expiresAt }
const soulhashStore = new Map(); // wallet → soulhash

// ─────────────────────────────────────────────────────────────
// RATE LIMIT SIMPLES (máx 5 req/min por IP)
// ─────────────────────────────────────────────────────────────
const ipRequests = new Map(); // ip → { count, resetAt }

function rateLimit(req, res, next) {
  const ip    = req.ip || req.connection.remoteAddress || 'unknown';
  const now   = Date.now();
  const entry = ipRequests.get(ip);

  if (!entry || now > entry.resetAt) {
    // Nova janela de 1 minuto
    ipRequests.set(ip, { count: 1, resetAt: now + 60_000 });
    return next();
  }

  if (entry.count >= 5) {
    return res.status(429).json({
      error: 'Muitas requisições. Aguarde 1 minuto.',
      retryAfter: Math.ceil((entry.resetAt - now) / 1000),
    });
  }

  entry.count++;
  next();
}

// Limpa entradas expiradas a cada 5 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipRequests) {
    if (now > entry.resetAt) ipRequests.delete(ip);
  }
  for (const [wallet, data] of nonceStore) {
    if (now > data.expiresAt) nonceStore.delete(wallet);
  }
}, 5 * 60_000);

// ─────────────────────────────────────────────────────────────
// MIDDLEWARES
// ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin:  process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST'],
}));
app.use(express.json({ limit: '10kb' }));

// ─────────────────────────────────────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────────────────────────────────────

/**
 * Valida endereço Ethereum (EIP-55 checksum)
 */
function isValidAddress(address) {
  try {
    return typeof address === 'string' && ethers.isAddress(address);
  } catch {
    return false;
  }
}

/**
 * Gera nonce aleatório único (hex 32 bytes)
 */
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Gera SoulHash fixo e determinístico vinculado à wallet
 * sha256(wallet + "SOULHASH-V2").slice(0, 24)
 * Normaliza para lowercase para consistência
 */
function generateSoulHash(wallet) {
  const normalized = wallet.toLowerCase();
  const hash = crypto
    .createHash('sha256')
    .update(normalized + 'SOULHASH-V2')
    .digest('hex');
  return hash.slice(0, 24).toUpperCase();
}

/**
 * Constrói a mensagem de login no padrão EIP-191
 * personal_sign assina: "\x19Ethereum Signed Message:\n" + len + message
 */
function buildLoginMessage(nonce) {
  return `Login SoulHash - nonce: ${nonce}`;
}

/**
 * Verifica assinatura EIP-191 via ethers.verifyMessage
 * Recupera o endereço que gerou a assinatura e compara com o wallet informado
 */
function verifySignature(wallet, message, signature) {
  try {
    const recovered = ethers.verifyMessage(message, signature);
    // Comparação case-insensitive (endereços Ethereum podem vir em casos diferentes)
    return recovered.toLowerCase() === wallet.toLowerCase();
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────────────────────

/**
 * GET /health
 * Verifica se a API está online
 */
app.get('/health', (req, res) => {
  res.json({ status: 'online', timestamp: new Date().toISOString() });
});

/**
 * POST /challenge
 * Recebe:  { wallet }
 * Retorna: { message, nonce }
 *
 * Gera um nonce único para a wallet assinar.
 * O nonce expira em 5 minutos.
 */
app.post('/challenge', rateLimit, (req, res) => {
  const { wallet } = req.body;

  // Validação
  if (!wallet || typeof wallet !== 'string') {
    return res.status(400).json({ error: 'Campo wallet é obrigatório.' });
  }

  if (!isValidAddress(wallet)) {
    return res.status(400).json({ error: 'Endereço de wallet inválido.' });
  }

  // Gera nonce e mensagem
  const nonce   = generateNonce();
  const message = buildLoginMessage(nonce);

  // Salva nonce com expiração de 5 minutos
  nonceStore.set(wallet.toLowerCase(), {
    nonce,
    expiresAt: Date.now() + 5 * 60_000,
  });

  return res.json({ message, nonce });
});

/**
 * POST /verify
 * Recebe:  { wallet, signature, message }
 * Retorna: { soulhash, wallet, isNew }
 *
 * Verifica a assinatura EIP-191.
 * Se válida: retorna (ou cria) o SoulHash vinculado à wallet.
 */
app.post('/verify', rateLimit, (req, res) => {
  const { wallet, signature, message } = req.body;

  // Validação dos campos
  if (!wallet || !signature || !message) {
    return res.status(400).json({
      error: 'Campos obrigatórios: wallet, signature, message.',
    });
  }

  if (!isValidAddress(wallet)) {
    return res.status(400).json({ error: 'Endereço de wallet inválido.' });
  }

  if (typeof signature !== 'string' || signature.length < 100) {
    return res.status(400).json({ error: 'Assinatura inválida.' });
  }

  // Verifica se existe nonce válido para esta wallet
  const walletKey = wallet.toLowerCase();
  const stored    = nonceStore.get(walletKey);

  if (!stored) {
    return res.status(401).json({
      error: 'Nonce não encontrado. Solicite um novo desafio via /challenge.',
    });
  }

  if (Date.now() > stored.expiresAt) {
    nonceStore.delete(walletKey);
    return res.status(401).json({
      error: 'Nonce expirado. Solicite um novo desafio via /challenge.',
    });
  }

  // Confirma que a mensagem recebida contém o nonce correto
  const expectedMessage = buildLoginMessage(stored.nonce);
  if (message !== expectedMessage) {
    return res.status(401).json({
      error: 'Mensagem não corresponde ao desafio emitido.',
    });
  }

  // Verifica assinatura com ethers.verifyMessage (EIP-191)
  const valid = verifySignature(wallet, message, signature);

  if (!valid) {
    return res.status(401).json({
      error: 'Assinatura inválida. A assinatura não pertence a esta wallet.',
    });
  }

  // Consome o nonce (não pode ser reutilizado)
  nonceStore.delete(walletKey);

  // Verifica se já existe SoulHash para esta wallet
  const isNew = !soulhashStore.has(walletKey);

  if (isNew) {
    // Gera e salva SoulHash determinístico vinculado à wallet
    const soulhash = generateSoulHash(wallet);
    soulhashStore.set(walletKey, soulhash);
  }

  const soulhash = soulhashStore.get(walletKey);

  return res.json({
    ok:       true,
    soulhash,
    wallet:   walletKey,
    isNew,
    message:  isNew
      ? '✦ SoulHash criado e vinculado à sua wallet.'
      : '✦ SoulHash existente recuperado.',
  });
});

/**
 * POST /login (compatibilidade com frontend anterior)
 * Atalho que aceita apenas { wallet } sem assinatura
 * Usado quando /nonce não está disponível no cliente
 */
app.post('/login', rateLimit, (req, res) => {
  const { wallet } = req.body;

  if (!wallet || !isValidAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida.' });
  }

  const walletKey = wallet.toLowerCase();
  const isNew     = !soulhashStore.has(walletKey);

  if (isNew) {
    soulhashStore.set(walletKey, generateSoulHash(wallet));
  }

  const soulhash = soulhashStore.get(walletKey);

  return res.json({
    ok:       true,
    soulhash,
    wallet:   walletKey,
    isNew,
    // Atributos iniciais da alma (derivados do soulhash)
    luz:        deriveAttr(soulhash, 0),
    sombra:     deriveAttr(soulhash, 1),
    equilibrio: deriveAttr(soulhash, 2),
    caos:       deriveAttr(soulhash, 3),
    empatia:    deriveAttr(soulhash, 4),
    hash_balance: 100, // bônus de entrada
    energy:     7,
    maxEnergy:  10,
    level:      1,
  });
});

/**
 * POST /choice
 * Recebe: { wallet, choice }
 * Retorna atributos atualizados conforme a escolha
 */
app.post('/choice', rateLimit, (req, res) => {
  const { wallet, choice } = req.body;

  if (!wallet || !isValidAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida.' });
  }

  const walletKey = wallet.toLowerCase();
  if (!soulhashStore.has(walletKey)) {
    return res.status(404).json({ error: 'Alma não encontrada. Faça login primeiro.' });
  }

  const VALID_CHOICES = ['light','shadow','balance','spin','coragem','sabedoria','empatia'];
  if (!VALID_CHOICES.includes(choice)) {
    return res.status(400).json({ error: `Escolha inválida. Opções: ${VALID_CHOICES.join(', ')}` });
  }

  // Retorna confirmação (lógica de atributos pode ser expandida com DB)
  return res.json({
    ok:     true,
    choice,
    wallet: walletKey,
    message: `Escolha '${choice}' registrada com sucesso.`,
  });
});

// ─────────────────────────────────────────────────────────────
// UTILITÁRIO — Deriva atributos da alma a partir do SoulHash
// ─────────────────────────────────────────────────────────────
function deriveAttr(soulhash, index) {
  const hash = crypto.createHash('sha256').update(soulhash).digest('hex');
  const vals = [0, 4, 8, 12, 16].map(i => parseInt(hash.slice(i, i + 4), 16));
  const raw  = vals.map(v => 15 + (v % 36));
  const sum  = raw.reduce((a, b) => a + b, 0);
  return Math.round((raw[index] / sum) * 180);
}

// ─────────────────────────────────────────────────────────────
// 404 handler
// ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Rota ${req.method} ${req.path} não encontrada.` });
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n[SoulHash API] ✦ Servidor rodando na porta ${PORT}`);
  console.log(`[SoulHash API] Rotas disponíveis:`);
  console.log(`  GET  /health`);
  console.log(`  POST /challenge  → gera nonce para assinatura`);
  console.log(`  POST /verify     → valida assinatura EIP-191`);
  console.log(`  POST /login      → login simplificado`);
  console.log(`  POST /choice     → registra escolha\n`);
});






