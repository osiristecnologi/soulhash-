/**
 * SOULHASH — Backend Seguro
 * Node.js + Express + Web3 Auth (Sign-In With Solana)
 *
 * Instalar: npm install express cors helmet express-rate-limit bs58 tweetnacl crypto dotenv
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

// ─────────────────────────────────────────────────────────────
// CONFIGURAÇÃO
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  PORT:            process.env.PORT || 3000,
  NONCE_TTL_MS:    5 * 60 * 1000,      // 5 minutos para usar o nonce
  SESSION_TTL_MS:  24 * 60 * 60 * 1000, // sessão válida por 24h
  APP_DOMAIN:      process.env.APP_DOMAIN || 'soulhash.app',
  SESSION_SECRET:  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
};

// ─────────────────────────────────────────────────────────────
// "DATABASE" (em produção: use PostgreSQL / Redis)
// ─────────────────────────────────────────────────────────────
const db = {
  nonces:   new Map(), // wallet → { nonce, expiresAt }
  sessions: new Map(), // sessionToken → { wallet, expiresAt }
  souls:    new Map(), // wallet → SoulData
  usedNonces: new Set(), // nonces já usados (anti-replay)
};

// ─────────────────────────────────────────────────────────────
// MIDDLEWARES DE SEGURANÇA
// ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // previne body bomb

// CORS — em produção, restringir ao domínio real
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST'],
}));

// Rate limit global
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente em 15 minutos.' },
}));

// Rate limit específico para rotas de auth (mais restrito)
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 10,
  message: { error: 'Muitas tentativas de autenticação.' },
});

// ─────────────────────────────────────────────────────────────
// UTILITÁRIOS
// ─────────────────────────────────────────────────────────────

/** Valida endereço Solana (base58, 32-44 chars) */
function isValidSolanaAddress(addr) {
  if (typeof addr !== 'string') return false;
  if (addr.length < 32 || addr.length > 44) return false;
  try { const decoded = bs58.decode(addr); return decoded.length === 32; }
  catch { return false; }
}

/** Gera nonce criptograficamente seguro */
function generateNonce() {
  return crypto.randomBytes(32).toString('hex');
}

/** Gera token de sessão */
function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

/**
 * Verifica assinatura Ed25519 da Phantom.
 * A mensagem assinada DEVE ter sido construída pelo frontend
 * com o nonce exato fornecido pelo backend.
 */
function verifySignature(wallet, message, signatureB58) {
  try {
    const publicKeyBytes = bs58.decode(wallet);
    const messageBytes   = new TextEncoder().encode(message);
    const sigBytes       = bs58.decode(signatureB58);
    return nacl.sign.detached.verify(messageBytes, sigBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Gera SoulHash DETERMINÍSTICO vinculado à wallet.
 * Usa HMAC-SHA256 com segredo do servidor → impossível de spoofar.
 * Mesmo wallet → mesmo hash. Sempre.
 */
function generateSoulHash(wallet) {
  const hmac = crypto.createHmac('sha256', CONFIG.SESSION_SECRET + ':SOULHASH');
  hmac.update(wallet);
  const hex = hmac.digest('hex');

  // Formata como A9F3-KL2X-77Q1
  const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let result = '';
  for (let i = 0; i < 12; i++) {
    result += chars[parseInt(hex.slice(i*2, i*2+2), 16) % chars.length];
    if (i === 3 || i === 7) result += '-';
  }
  return result;
}

/**
 * Deriva atributos iniciais da alma a partir do SoulHash.
 * Determinístico — nunca muda para o mesmo wallet.
 */
function deriveInitialAttrs(soulhash) {
  const hash = crypto.createHash('sha256').update(soulhash).digest('hex');
  const vals = [0,4,8,12,16].map(i => parseInt(hash.slice(i, i+4), 16));
  const raw  = vals.map(v => 15 + (v % 35));
  const sum  = raw.reduce((a,b) => a+b, 0);
  const norm = raw.map(v => Math.round(v / sum * 175));
  return { luz: norm[0], sombra: norm[1], equilibrio: norm[2], caos: norm[3], empatia: norm[4] };
}

/** Middleware: exige sessão válida */
function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ error: 'Sessão ausente.' });

  const session = db.sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Sessão inválida.' });
  if (Date.now() > session.expiresAt) {
    db.sessions.delete(token);
    return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }

  req.wallet = session.wallet;
  next();
}

// ─────────────────────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────────────────────

/**
 * GET /nonce?wallet=<ADDRESS>
 * Gera um nonce único para o wallet assinar.
 * Anti-replay: cada nonce expira em 5 min e só pode ser usado 1 vez.
 */
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;

  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Endereço de wallet inválido.' });
  }

  const nonce     = generateNonce();
  const expiresAt = Date.now() + CONFIG.NONCE_TTL_MS;

  db.nonces.set(wallet, { nonce, expiresAt });

  // Mensagem estruturada no padrão Sign-In With Solana (SIWS)
  const message = [
    `${CONFIG.APP_DOMAIN} solicita sua autenticação.`,
    ``,
    `Wallet: ${wallet}`,
    `Nonce: ${nonce}`,
    `Emitido em: ${new Date().toISOString()}`,
    `Válido por: 5 minutos`,
    ``,
    `Ao assinar, você confirma que é o dono desta wallet.`,
    `Esta assinatura não autoriza nenhuma transação.`,
  ].join('\n');

  return res.json({ nonce, message });
});

/**
 * POST /login
 * Body: { wallet, signature, nonce }
 * - Verifica que o nonce é válido e não foi usado
 * - Verifica assinatura criptográfica
 * - Cria sessão autenticada
 * - Retorna SoulHash e dados da alma
 */
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  // 1. Validar inputs
  if (!isValidSolanaAddress(wallet)) {
    return res.status(400).json({ error: 'Wallet inválida.' });
  }
  if (typeof signature !== 'string' || signature.length < 64) {
    return res.status(400).json({ error: 'Assinatura ausente ou inválida.' });
  }
  if (typeof nonce !== 'string' || nonce.length !== 64) {
    return res.status(400).json({ error: 'Nonce inválido.' });
  }

  // 2. Verificar se nonce foi usado antes (anti-replay)
  if (db.usedNonces.has(nonce)) {
    return res.status(401).json({ error: 'Nonce já utilizado. Solicite um novo.' });
  }

  // 3. Verificar se nonce pertence a esta wallet e não expirou
  const nonceData = db.nonces.get(wallet);
  if (!nonceData) {
    return res.status(401).json({ error: 'Nonce não encontrado. Solicite um novo.' });
  }
  if (nonceData.nonce !== nonce) {
    return res.status(401).json({ error: 'Nonce não corresponde.' });
  }
  if (Date.now() > nonceData.expiresAt) {
    db.nonces.delete(wallet);
    return res.status(401).json({ error: 'Nonce expirado. Solicite um novo.' });
  }

  // 4. Reconstruir mensagem exata que foi assinada
  const message = [
    `${CONFIG.APP_DOMAIN} solicita sua autenticação.`,
    ``,
    `Wallet: ${wallet}`,
    `Nonce: ${nonce}`,
    `Emitido em: ${new Date(nonceData.expiresAt - CONFIG.NONCE_TTL_MS).toISOString()}`,
    `Válido por: 5 minutos`,
    ``,
    `Ao assinar, você confirma que é o dono desta wallet.`,
    `Esta assinatura não autoriza nenhuma transação.`,
  ].join('\n');

  // 5. Verificar assinatura criptográfica
  const valid = verifySignature(wallet, message, signature);
  if (!valid) {
    return res.status(401).json({ error: 'Assinatura inválida. Autenticação recusada.' });
  }

  // 6. Consumir nonce (marca como usado — nunca pode ser reutilizado)
  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  // 7. Criar sessão autenticada
  const sessionToken = generateSessionToken();
  db.sessions.set(sessionToken, {
    wallet,
    expiresAt: Date.now() + CONFIG.SESSION_TTL_MS,
  });

  // 8. Buscar ou criar alma do jogador
  if (!db.souls.has(wallet)) {
    const soulhash = generateSoulHash(wallet);
    db.souls.set(wallet, {
      soulhash,
      wallet,
      createdAt:   new Date().toISOString(),
      attrs:       deriveInitialAttrs(soulhash),
      stats:       { missoes: 0, escolhas: 0, almas: 0, confrontos: 0, xp: 0 },
      fase_atual:  1,
      p1_choice:   null,
      p2_choice:   null,
      coins: 100, // bônus inicial
    });
}); 
  const soul = db.souls.get(wallet);

  return res.json({
    sessionToken,
    soulhash:   soul.soulhash,
    createdAt:  soul.createdAt,
    attrs:      soul.attrs,
    stats:      soul.stats,
    fase_atual: soul.fase_atual,
    p1_choice:  soul.p1_choice,
    p2_choice:  soul.p2_choice,
    });
});

/**
 * POST /choice
 * Header: x-session-token: <token>
 * Body: { choice }
 * - Requer sessão válida (não aceita wallet do body)
 * - Backend valida fase e se escolha já foi feita
 * - Backend é o único a modificar atributos
 */
app.post('/choice', requireSession, (req, res) => {
  const { choice } = req.body;
  const wallet = req.wallet; // extraído da sessão, NÃO do body

  if (typeof choice !== 'string') {
    return res.status(400).json({ error: 'Escolha inválida.' });
  }

  const soul = db.souls.get(wallet);
  if (!soul) {
    return res.status(404).json({ error: 'Alma não encontrada. Faça login primeiro.' });
  }

  // Definição de fases
  const FASES = {
    1: {
      choices: ['light', 'shadow', 'balance'],
      field: 'p1_choice',
      apply: (attrs, choice) => {
        const a = { ...attrs };
        if (choice === 'light')   { a.luz = Math.min(100, a.luz+20); a.empatia = Math.min(100, a.empatia+10); }
        if (choice === 'shadow')  { a.sombra = Math.min(100, a.sombra+20); a.caos = Math.min(100, a.caos+10); }
        if (choice === 'balance') { a.equilibrio = Math.min(100, a.equilibrio+25); }
        return a;
      },
      xp: 20, missoes: 1,
    },
    2: {
      choices: ['coragem', 'sabedoria', 'empatia'],
      field: 'p2_choice',
      apply: (attrs, choice) => {
        const a = { ...attrs };
        if (choice === 'coragem')   { a.caos = Math.min(100, a.caos+15); a.luz = Math.min(100, a.luz+10); }
        if (choice === 'sabedoria') { a.equilibrio = Math.min(100, a.equilibrio+15); }
        if (choice === 'empatia')   { a.empatia = Math.min(100, a.empatia+20); a.sombra = Math.max(0, a.sombra-5); }
        return a;
      },
      xp: 25, confrontos: 1,
    },
  };

  const fase = FASES[soul.fase_atual];
  if (!fase) {
    return res.status(400).json({ error: 'Não há fase ativa no momento.' });
  }

  // Verificar se escolha é válida para esta fase
  if (!fase.choices.includes(choice)) {
    return res.status(400).json({
      error: `Escolha '${choice}' inválida para fase ${soul.fase_atual}.`,
      validas: fase.choices,
    });
  }

  // Verificar se já fez escolha nesta fase
  if (soul[fase.field] !== null) {
    return res.status(409).json({
      error: `Você já fez sua escolha na fase ${soul.fase_atual}.`,
      escolha_feita: soul[fase.field],
    });
  }

  // Verificar progressão em ordem (fase 2 exige fase 1 completa)
  if (soul.fase_atual === 2 && soul.p1_choice === null) {
    return res.status(403).json({ error: 'Complete a fase 1 primeiro.' });
  }

  // Aplicar escolha — APENAS o backend modifica os atributos
  soul[fase.field]  = choice;
  soul.attrs        = fase.apply(soul.attrs, choice);
  soul.stats.xp     += fase.xp;
  soul.stats.escolhas++;
  if (fase.missoes)    soul.stats.missoes++;
  if (fase.confrontos) soul.stats.confrontos++;

  // Avançar fase
  if (soul.fase_atual < Object.keys(FASES).length) {
    soul.fase_atual++;
  }

  db.souls.set(wallet, soul);

  return res.json({
    ok:         true,
    attrs:      soul.attrs,
    stats:      soul.stats,
    fase_atual: soul.fase_atual,
    p1_choice:  soul.p1_choice,
    p2_choice:  soul.p2_choice,
  });
});

/**
 * GET /me
 * Header: x-session-token
 * Retorna estado atual da alma (útil para reconexão)
 */
app.get('/me', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);
  if (!soul) return res.status(404).json({ error: 'Alma não encontrada.' });

  return res.json({
    soulhash:   soul.soulhash,
    createdAt:  soul.createdAt,
    attrs:      soul.attrs,
    stats:      soul.stats,
    fase_atual: soul.fase_atual,
    p1_choice:  soul.p1_choice,
    p2_choice:  soul.p2_choice,
  });
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
app.listen(CONFIG.PORT, () => {
  console.log(`[SoulHash API] Rodando na porta ${CONFIG.PORT}`);
  console.log(`[SoulHash API] Domínio: ${CONFIG.APP_DOMAIN}`);
});

