/**
 * SOULHASH v2 — Backend Seguro
 * SoulHash gerado IMEDIATAMENTE ao conectar wallet
 * Formato: WALLET_PREFIX — HASH_SUFFIX (vinculado e único)
 *
 * npm install express cors helmet express-rate-limit bs58 tweetnacl crypto dotenv
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

// ─────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  PORT:           process.env.PORT || 3000,
  NONCE_TTL_MS:   5  * 60 * 1000,
  SESSION_TTL_MS: 24 * 60 * 60 * 1000,
  APP_DOMAIN:     process.env.APP_DOMAIN || 'soulhash.app',
  HMAC_SECRET: process.env.HMAC_SECRET || (() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('HMAC_SECRET must be set in production!');
    }
    return crypto.randomBytes(64).toString('hex');
  })(),
};

// ─────────────────────────────────────────────────────────────
// DB (produção: PostgreSQL + Redis)
// ─────────────────────────────────────────────────────────────
const db = {
  nonces:     new Map(),
  sessions:   new Map(),
  souls:      new Map(),
  usedNonces: new Set(),
};

// ─────────────────────────────────────────────────────────────
// MIDDLEWARES
// ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*', methods: ['GET','POST'] }));

app.use(rateLimit({ windowMs: 15*60*1000, max: 150, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas requisições.' } }));

const authLimiter    = rateLimit({ windowMs: 60*1000, max: 10,  message: { error: 'Muitas tentativas de auth.' } });
const previewLimiter = rateLimit({ windowMs: 60*1000, max: 30,  message: { error: 'Muitas consultas de preview.' } });

// ─────────────────────────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────────────────────────

function isValidSolanaAddress(addr) {
  if (typeof addr !== 'string' || addr.length < 32 || addr.length > 44) return false;
  try { return bs58.decode(addr).length === 32; } catch { return false; }
}

/**
 * GERA SOULHASH VINCULADO À WALLET
 *
 * Formato: ABC123 — X7K4M2PQ
 *          ↑ 6 chars do endereço (identificável)
 *                    ↑ 8 chars HMAC-SHA256(wallet, server_secret)
 *
 * Segurança:
 * - HMAC impede que qualquer um calcule o hash sem o segredo do servidor
 * - Prefixo da wallet torna o SoulHash rastreável ao dono
 * - Namespace 'SOULHASH_V2' evita colisão com outros usos do segredo
 */
function generateSoulHash(wallet) {
  const prefix  = wallet.slice(0, 6).toUpperCase();
  const hmac    = crypto.createHmac('sha256', CONFIG.HMAC_SECRET);
  hmac.update('SOULHASH_V2:' + wallet);
  const fullHex = hmac.digest('hex');
  const CHARS   = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let suffix    = '';
  for (let i = 0; i < 8; i++) {
    suffix += CHARS[parseInt(fullHex.slice(i*2, i*2+2), 16) % CHARS.length];
  }
  return `${prefix}-${suffix.slice(0,4)}-${suffix.slice(4)}`;
}

function generateNonce()        { return crypto.randomBytes(32).toString('hex'); }
function generateSessionToken() { return crypto.randomBytes(48).toString('hex'); }

function verifySignature(wallet, message, signatureB58) {
  try {
    const pub = bs58.decode(wallet);
    const msg = new TextEncoder().encode(message);
    const sig = bs58.decode(signatureB58);
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch { return false; }
}

function deriveAttrs(soulhash) {
  const h    = crypto.createHash('sha256').update(soulhash).digest('hex');
  const vals = [0,4,8,12,16].map(i => parseInt(h.slice(i,i+4),16));
  const raw  = vals.map(v => 15 + (v % 36));
  const sum  = raw.reduce((a,b)=>a+b,0);
  const n    = raw.map(v => Math.round(v/sum*180));
  return { luz:n[0], sombra:n[1], equilibrio:n[2], caos:n[3], empatia:n[4] };
}

function requireSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || token.length < 80) return res.status(401).json({ error: 'Sessão ausente.' });
  const s = db.sessions.get(token);
  if (!s)                    return res.status(401).json({ error: 'Sessão inválida.' });
  if (Date.now() > s.expiresAt) { db.sessions.delete(token); return res.status(401).json({ error: 'Sessão expirada.' }); }
  req.wallet = s.wallet;
  next();
}

// ─────────────────────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────────────────────

/**
 * GET /preview-hash?wallet=ADDRESS
 * Retorna o SoulHash imediatamente ao conectar a wallet
 * Sem autenticação — hash é público por natureza (como endereço ENS)
 * O usuário vê seu hash ANTES de assinar
 */
app.get('/preview-hash', previewLimiter, (req, res) => {
  const { wallet } = req.query;
  if (!isValidSolanaAddress(wallet))
    return res.status(400).json({ error: 'Wallet inválida.' });

  return res.json({
    soulhash:       generateSoulHash(wallet),
    wallet_display: wallet.slice(0,6) + '...' + wallet.slice(-4),
    preview:        true,
  });
});

/**
 * GET /nonce?wallet=ADDRESS
 * Nonce inclui o SoulHash na mensagem assinada
 * → vincula assinatura ao hash definitivamente
 */
app.get('/nonce', authLimiter, (req, res) => {
  const { wallet } = req.query;
  if (!isValidSolanaAddress(wallet))
    return res.status(400).json({ error: 'Wallet inválida.' });

  const nonce     = generateNonce();
  const issuedAt  = new Date();
  const soulhash  = generateSoulHash(wallet);

  db.nonces.set(wallet, { nonce, issuedAt: issuedAt.toISOString(), expiresAt: Date.now() + CONFIG.NONCE_TTL_MS });

  const message = [
    `${CONFIG.APP_DOMAIN} — Autenticação SoulHash`,
    ``,
    `Wallet:   ${wallet}`,
    `SoulHash: ${soulhash}`,
    `Nonce:    ${nonce}`,
    `Emitido:  ${issuedAt.toISOString()}`,
    `Expira:   5 minutos`,
    ``,
    `Ao assinar você confirma ser o dono desta wallet`,
    `e aceita vincular este SoulHash à sua identidade.`,
    `Nenhuma transação será realizada.`,
  ].join('\n');

  return res.json({ nonce, message, soulhash });
});

/**
 * POST /login
 * Body: { wallet, signature, nonce }
 * Verifica assinatura → cria sessão → retorna alma completa
 */
app.post('/login', authLimiter, (req, res) => {
  const { wallet, signature, nonce } = req.body;

  if (!isValidSolanaAddress(wallet))
    return res.status(400).json({ error: 'Wallet inválida.' });
  if (typeof signature !== 'string' || signature.length < 64)
    return res.status(400).json({ error: 'Assinatura inválida.' });
  if (typeof nonce !== 'string' || nonce.length !== 64)
    return res.status(400).json({ error: 'Nonce inválido.' });
  if (db.usedNonces.has(nonce))
    return res.status(401).json({ error: 'Nonce já utilizado.' });

  const nd = db.nonces.get(wallet);
  if (!nd || nd.nonce !== nonce)
    return res.status(401).json({ error: 'Nonce não encontrado.' });
  if (Date.now() > nd.expiresAt) {
    db.nonces.delete(wallet);
    return res.status(401).json({ error: 'Nonce expirado.' });
  }

  const soulhash = generateSoulHash(wallet);
  const message  = [
    `${CONFIG.APP_DOMAIN} — Autenticação SoulHash`,
    ``,
    `Wallet:   ${wallet}`,
    `SoulHash: ${soulhash}`,
    `Nonce:    ${nonce}`,
    `Emitido:  ${new Date(nd.issuedAt).toISOString()}`,
    `Expira:   5 minutos`,
    ``,
    `Ao assinar você confirma ser o dono desta wallet`,
    `e aceita vincular este SoulHash à sua identidade.`,
    `Nenhuma transação será realizada.`,
  ].join('\n');

  if (!verifySignature(wallet, message, signature))
    return res.status(401).json({ error: 'Assinatura inválida. Autenticação recusada.' });

  // Consome nonce
  db.usedNonces.add(nonce);
  db.nonces.delete(wallet);

  // Cria sessão
  const sessionToken = generateSessionToken();
  db.sessions.set(sessionToken, { wallet, expiresAt: Date.now() + CONFIG.SESSION_TTL_MS });

  // Cria ou recupera alma
  let isNewSoul = false;
  if (!db.souls.has(wallet)) {
    isNewSoul = true;
    db.souls.set(wallet, {
      soulhash,
      wallet_display: wallet.slice(0,6) + '...' + wallet.slice(-4),
      createdAt:    new Date().toISOString(),
      attrs:        deriveAttrs(soulhash),
      stats:        { missoes:0, escolhas:0, almas:0, confrontos:0, xp:0 },
      hash_balance: 100,   // ← bônus de entrada
      gems:         0,
      energy:       7,
      maxEnergy:    10,
      level:        1,
      phase:        1,
      phasePassed:  false,
      spins:        0,
      ownedCards:   {},
      dimProgress:  0,
      fase_atual:   1,
      p1_choice:    null,
      p2_choice:    null,
    });
  }

  const soul = db.souls.get(wallet);
  const { wallet: _w, ...safeData } = soul; // nunca retorna wallet completa

  return res.json({ sessionToken, isNewSoul, ...safeData });
});

/** GET /me */
app.get('/me', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);
  if (!soul) return res.status(404).json({ error: 'Alma não encontrada.' });
  const { wallet: _w, ...safeData } = soul;
  return res.json(safeData);
});

/** POST /spin — resultado calculado SOMENTE no servidor */
app.post('/spin', requireSession, (req, res) => {
  const soul = db.souls.get(req.wallet);
  if (!soul)             return res.status(404).json({ error: 'Alma não encontrada.' });
  if (soul.energy <= 0)  return res.status(400).json({ error: 'Sem energia.' });

  soul.energy--;
  soul.spins++;

  const result      = computeSpinResult();
  soul.stats.xp    += 10;
  soul.dimProgress += 25;

  if (result.isWin) {
    soul.hash_balance            += result.reward;
    soul.stats.xp                += 30;
    soul.dimProgress             += 50;
    soul.phasePassed              = true;
    if (result.cardWon)
      soul.ownedCards[result.cardWon] = (soul.ownedCards[result.cardWon] || 0) + 1;
  }

  soul.level = Math.floor(soul.stats.xp / 1000) + 1;
  db.souls.set(req.wallet, soul);

  return res.json({
    ok: true, result,
    hash_balance: soul.hash_balance,
    energy:       soul.energy,
    maxEnergy:    soul.maxEnergy,
    stats:        soul.stats,
    level:        soul.level,
    dimProgress:  soul.dimProgress,
    phasePassed:  soul.phasePassed,
    ownedCards:   soul.ownedCards,
  });
});

/** POST /choice */
app.post('/choice', requireSession, (req, res) => {
  const { choice } = req.body;
  const soul = db.souls.get(req.wallet);
  if (!soul) return res.status(404).json({ error: 'Alma não encontrada.' });

  const FASES = {
    1: { choices:['light','shadow','balance'], field:'p1_choice', xp:20, missoes:1,
      apply(a,c){ const r={...a};
        if(c==='light')  {r.luz=Math.min(100,r.luz+20);r.empatia=Math.min(100,r.empatia+10);}
        if(c==='shadow') {r.sombra=Math.min(100,r.sombra+20);r.caos=Math.min(100,r.caos+10);}
        if(c==='balance'){r.equilibrio=Math.min(100,r.equilibrio+25);}
        return r; } },
    2: { choices:['coragem','sabedoria','empatia'], field:'p2_choice', xp:25, confrontos:1,
      apply(a,c){ const r={...a};
        if(c==='coragem')  {r.caos=Math.min(100,r.caos+15);r.luz=Math.min(100,r.luz+10);}
        if(c==='sabedoria'){r.equilibrio=Math.min(100,r.equilibrio+15);}
        if(c==='empatia')  {r.empatia=Math.min(100,r.empatia+20);r.sombra=Math.max(0,r.sombra-5);}
        return r; } },
  };

  const fase = FASES[soul.fase_atual];
  if (!fase) return res.status(400).json({ error: 'Fase inativa.' });
  if (!fase.choices.includes(choice)) return res.status(400).json({ error: 'Escolha inválida.', validas: fase.choices });
  if (soul[fase.field] !== null) return res.status(409).json({ error: 'Fase já concluída.', escolha_feita: soul[fase.field] });
  if (soul.fase_atual === 2 && !soul.p1_choice) return res.status(403).json({ error: 'Complete a fase 1 primeiro.' });

  soul[fase.field]    = choice;
  soul.attrs          = fase.apply(soul.attrs, choice);
  soul.stats.xp      += fase.xp;
  soul.stats.escolhas++;
  if (fase.missoes)    soul.stats.missoes++;
  if (fase.confrontos) soul.stats.confrontos++;
  if (soul.fase_atual < 2) soul.fase_atual++;
  db.souls.set(req.wallet, soul);

  return res.json({ ok:true, attrs:soul.attrs, stats:soul.stats, fase_atual:soul.fase_atual, p1_choice:soul.p1_choice, p2_choice:soul.p2_choice });
});

// ─────────────────────────────────────────────────────────────
// LÓGICA DO SPIN (somente servidor)
// ─────────────────────────────────────────────────────────────
const CARD_IDS = ['luz','sombra','caos','empatia','equil'];
const rand = () => CARD_IDS[Math.floor(Math.random() * CARD_IDS.length)];

function hasWin(g) {
  return [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]]
    .some(([a,b,c]) => g[a] && g[a]===g[b] && g[b]===g[c]);
}

function computeSpinResult() {
  const isWin = Math.random() < 0.30;
  const grid  = Array(9).fill(null).map(rand);

  if (!isWin) {
    let t = 0;
    while (hasWin(grid) && t++ < 50) for (let i=0;i<9;i++) grid[i]=rand();
    return { isWin:false, grid, combo:'none', winPositions:[], reward:0, cardWon:null };
  }

  const roll   = Math.random();
  const winner = rand();

  if (roll < 0.55) {
    const row = Math.floor(Math.random()*3);
    grid[row*3]=grid[row*3+1]=grid[row*3+2]=winner;
    return { isWin:true, grid, combo:'3linha', winPositions:[row*3,row*3+1,row*3+2], reward:50, cardWon:winner };
  } else if (roll < 0.80) {
    const d = Math.random()<.5?[0,4,8]:[2,4,6];
    d.forEach(i=>grid[i]=winner);
    return { isWin:true, grid, combo:'diagonal', winPositions:d, reward:80, cardWon:winner };
  } else if (roll < 0.93) {
    [0,2,4,6,8].forEach(i=>grid[i]=winner);
    return { isWin:true, grid, combo:'cruz', winPositions:[0,2,4,6,8], reward:120, cardWon:winner };
  } else {
    CARD_IDS.forEach((id,i)=>{grid[i]=id; if(i+5<9) grid[i+5]=rand();});
    return { isWin:true, grid, combo:'todos', winPositions:[0,1,2,3,4,5,6,7,8], reward:60, cardWon:winner };
  }
}

app.listen(CONFIG.PORT, () =>
  console.log(`[SoulHash v2] :${CONFIG.PORT} | SoulHash = wallet_prefix + HMAC-SHA256`)
);


