require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bs58 = require("bs58");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const API_URL = process.env.API_URL || 'https://soulhash-api.onrender.com';

// ═══════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════
app.use(express.json({ limit: "10kb" }));
app.use(cors({ 
  origin: function(origin, callback) {
    const allowed = (process.env.ALLOWED_ORIGIN || 'http://localhost:8080,http://localhost:3000').split(',');
    if (!origin || allowed.indexOf(origin) !== -1) return callback(null, true);
    callback(new Error('CORS não permitido'));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Session-Token"]
}));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 60_000, max: 15 });

// Serve frontend estático (para deploy único)
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════
// CONSTANTES DO JOGO
// ═══════════════════════════════════════════════════════
const GAME = {
  MAX_ENERGY: 100,
  ENERGY_COST: 10,
  ENERGY_REGEN: 1,
  BONUS_WIN: 20,
  BONUS_LOSE: 5,
  CRYSTAL_BONUS_HASH: 500,
  CRYSTAL_BONUS_USD: 20,
  CRYSTAL_CHANCE: 0.01,
  WIN_PROBABILITY: 0.30,
  INITIAL_BALANCE: 100,
  WITHDRAW_MIN: 50
};

const CARDS = ["LUZ", "SOMBRA", "CAOS", "EMPATIA", "EQUILIBRIO"];
const CRYSTAL_CARD = "CRISTAL";

// ═══════════════════════════════════════════════════════
// STORAGE EM MEMÓRIA (Produção: PostgreSQL + Redis)
// ═══════════════════════════════════════════════════════
const challenges = new Map();
const sessions = new Map();
const walletToSoulhash = new Map();
const soulhashToWallet = new Map();
const balances = new Map();
const energyStore = new Map();
const lastEnergyUpdate = new Map();
const statsStore = new Map();
const crystalWins = new Map();

// ═══════════════════════════════════════════════════════
// UTILITÁRIOS
// ═══════════════════════════════════════════════════════
function isValidWallet(w) {
  return typeof w === "string" && w.length >= 32 && w.length <= 64;
}

function generateSoulHash(wallet) {
  return crypto.createHash("sha256").update(wallet.trim().toLowerCase()).digest("hex");
}

function requireSession(req, res, next) {
  const token = req.headers["x-session-token"];
  const wallet = sessions.get(token);
  if (!wallet) return res.status(401).json({ error: "Sessão inválida ou expirada." });
  req.wallet = wallet;
  req.soulhash = walletToSoulhash.get(wallet);
  next();
}

function getEnergy(soulhash) {
  const now = Date.now();
  let energy = energyStore.get(soulhash) ?? GAME.MAX_ENERGY;
  const lastUpdate = lastEnergyUpdate.get(soulhash) ?? now;
  const minutesPassed = Math.floor((now - lastUpdate) / 60000);
  if (minutesPassed > 0) {
    energy = Math.min(GAME.MAX_ENERGY, energy + minutesPassed * GAME.ENERGY_REGEN);
    energyStore.set(soulhash, energy);
    lastEnergyUpdate.set(soulhash, now);
  }
  return energy;
}

function calcLevel(xp) { return Math.floor(xp / 1000) + 1; }

// ═══════════════════════════════════════════════════════
// LÓGICA DO SPIN (SERVER-SIDE - ANTI-CHEAT)
// ═══════════════════════════════════════════════════════
function computeSpin() {
  let isWin = Math.random() < GAME.WIN_PROBABILITY;
  let hasCrystal = false, crystalInCenter = false;

  const grid = Array.from({ length: 9 }, () => {
    if (Math.random() < GAME.CRYSTAL_CHANCE) { hasCrystal = true; return CRYSTAL_CARD; }
    return CARDS[Math.floor(Math.random() * CARDS.length)];
  });

  const WIN_LINES = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  let winPositions = [], combo = "none";

  if (grid[4] === CRYSTAL_CARD) { crystalInCenter = true; isWin = true; }

  if (isWin && !crystalInCenter) {
    const lineIdx = Math.floor(Math.random() * WIN_LINES.length);
    const [a, b, c] = WIN_LINES[lineIdx];
    let winner = (grid[a]===CRYSTAL_CARD||grid[b]===CRYSTAL_CARD||grid[c]===CRYSTAL_CARD) 
      ? CRYSTAL_CARD : CARDS[Math.floor(Math.random() * CARDS.length)];
    grid[a] = grid[b] = grid[c] = winner;
    winPositions = [a, b, c];
    combo = winner === CRYSTAL_CARD ? "crystal_line" : "3linha";
  } else if (!isWin) {
    if (grid[4] === CRYSTAL_CARD) grid[4] = CARDS[Math.floor(Math.random() * CARDS.length)];
    let tries = 0;
    while (tries++ < 50) {
      let hasWin = false;
      for (const [a,b,c] of WIN_LINES) {
        if (grid[a] === grid[b] && grid[b] === grid[c]) { hasWin = true; break; }
      }
      if (!hasWin) break;
      for (let i = 0; i < 9; i++) if (grid[i] !== CRYSTAL_CARD) 
        grid[i] = CARDS[Math.floor(Math.random() * CARDS.length)];
    }
  }
  return { grid, isWin, winPositions, combo, hasCrystal, crystalInCenter };
}

// ═══════════════════════════════════════════════════════
// ROTAS DA API
// ═══════════════════════════════════════════════════════

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "SoulHash Arena API", version: "1.0.0", timestamp: new Date().toISOString() });
});

app.post("/challenge", authLimiter, (req, res) => {
  const { wallet } = req.body;
  if (!isValidWallet(wallet)) return res.status(400).json({ error: "Wallet inválida." });
  const message = `SoulHash:${wallet}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
  challenges.set(wallet, { message, used: false, createdAt: Date.now() });
  setTimeout(() => challenges.delete(wallet), 300000);
  res.json({ message });
});

app.post("/verify", authLimiter, async (req, res) => {
  const { wallet, signature } = req.body;
  if (!isValidWallet(wallet)) return res.status(400).json({ error: "Wallet inválida." });
  if (!signature) return res.status(401).json({ error: "Assinatura ausente." });
  
  const entry = challenges.get(wallet);
  if (!entry) return res.status(400).json({ error: "Sem challenge. Chame /challenge primeiro." });
  if (entry.used) return res.status(400).json({ error: "Challenge já utilizado." });

  try {
    const sigBuf = bs58.decode(signature);
    if (sigBuf.length < 32) throw new Error("Assinatura inválida");
  } catch { return res.status(401).json({ error: "Assinatura inválida." }); }

  entry.used = true;
  const soulhash = generateSoulHash(wallet);
  const isNew = !walletToSoulhash.has(wallet);
  
  walletToSoulhash.set(wallet, soulhash);
  soulhashToWallet.set(soulhash, wallet);
  
  if (isNew) {
    balances.set(soulhash, GAME.INITIAL_BALANCE);
    energyStore.set(soulhash, GAME.MAX_ENERGY);
    lastEnergyUpdate.set(soulhash, Date.now());
    statsStore.set(soulhash, { spins: 0, wins: 0, xp: 0, crystals: 0 });
    crystalWins.set(soulhash, 0);
    console.log(`[NEW] ${wallet.slice(0,8)}... → ${soulhash.slice(0,16)}...`);
  } else {
    energyStore.set(soulhash, getEnergy(soulhash));
    lastEnergyUpdate.set(soulhash, Date.now());
  }

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, wallet);
  setTimeout(() => sessions.delete(token), 86400000);

  const stats = statsStore.get(soulhash);
  res.json({
    sessionToken: token, soulhash, isNew,
    balance: balances.get(soulhash), energy: getEnergy(soulhash), maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp), stats,
    message: isNew ? "Bem-vindo! +100 Hash bônus!" : "Bem-vindo de volta!"
  });
});

app.post("/spin", requireSession, (req, res) => {
  const { soulhash } = req;
  const currentEnergy = getEnergy(soulhash);
  if (currentEnergy < GAME.ENERGY_COST) {
    return res.status(400).json({ error: "Energia insuficiente. Aguarde recarga (1/min).", currentEnergy, required: GAME.ENERGY_COST });
  }

  const { grid, isWin, winPositions, combo, hasCrystal, crystalInCenter } = computeSpin();
  const newEnergy = currentEnergy - GAME.ENERGY_COST;
  energyStore.set(soulhash, newEnergy);
  lastEnergyUpdate.set(soulhash, Date.now());

  let reward = 0, crystalWin = false, usdBonus = 0;
  if (crystalInCenter) {
    reward = GAME.CRYSTAL_BONUS_HASH; usdBonus = GAME.CRYSTAL_BONUS_USD; crystalWin = true;
    crystalWins.set(soulhash, (crystalWins.get(soulhash)||0) + 1);
    console.log(`[CRYSTAL!] ${soulhash.slice(0,16)}... +${reward} hash + $${usdBonus}`);
  } else if (isWin) reward = GAME.BONUS_WIN; else reward = GAME.BONUS_LOSE;

  const newBalance = (balances.get(soulhash)||0) + reward;
  balances.set(soulhash, newBalance);

  const stats = statsStore.get(soulhash) || { spins:0, wins:0, xp:0, crystals:0 };
  stats.spins++; if (isWin||crystalInCenter) stats.wins++;
  if (crystalInCenter) stats.crystals++;
  stats.xp += crystalInCenter ? 500 : (isWin ? 40 : 10);
  statsStore.set(soulhash, stats);

  res.json({
    grid, isWin: isWin||crystalInCenter, winPositions,
    combo: crystalInCenter ? "crystal_center" : combo,
    reward, crystalWin, usdBonus, hasCrystal, crystalInCenter,
    balance: newBalance, energy: newEnergy, maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp), stats,
    message: crystalInCenter ? "🎉 CRISTAL! +500 Hash + $20!" : 
             isWin ? `Vitória! +${reward} Hash` : `Derrota. +${reward} Hash`
  });
});

app.post("/reward", requireSession, (req, res) => {
  const { soulhash, wallet } = req;
  const { amount, address } = req.body;
  if (!amount || isNaN(amount) || amount < GAME.WITHDRAW_MIN) {
    return res.status(400).json({ error: `Mínimo: ${GAME.WITHDRAW_MIN} Hash.`, minimum: GAME.WITHDRAW_MIN });
  }
  const balance = balances.get(soulhash) || 0;
  if (balance < amount) return res.status(400).json({ error: "Saldo insuficiente.", balance, requested: amount });

  balances.set(soulhash, balance - amount);
  const txHash = `SOL_${crypto.randomBytes(16).toString("hex").toUpperCase()}`;
  console.log(`[WITHDRAW] ${amount} Hash → ${address||wallet} | TX: ${txHash}`);

  res.json({ success: true, paidTo: address||wallet, amount, remainingBalance: balance-amount, txHash, timestamp: new Date().toISOString() });
});

app.get("/me", requireSession, (req, res) => {
  const { soulhash, wallet } = req;
  const stats = statsStore.get(soulhash) || { spins:0, wins:0, xp:0, crystals:0 };
  res.json({
    soulhash, wallet: wallet.slice(0,6)+"..."+wallet.slice(-4),
    balance: balances.get(soulhash)||0, energy: getEnergy(soulhash), maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp), stats, crystalWins: crystalWins.get(soulhash)||0
  });
});

app.get("/stats", (req, res) => {
  let totalSpins=0, totalCrystals=0;
  for (const s of statsStore.values()) { totalSpins+=s.spins; totalCrystals+=s.crystals||0; }
  res.json({ totalUsers: walletToSoulhash.size, totalSpins, totalCrystals, activeSessions: sessions.size });
});

// Fallback para SPA
app.get('*', (req, res) => {
  if (req.path.includes('.') || req.path.startsWith('/api')) return res.status(404).json({error: "Not found"});
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error("[ERROR]", err);
  res.status(500).json({ error: "Erro interno", message: process.env.NODE_ENV==='development'?err.message:undefined });
});

// ═══════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║  SOULHASH ARENA API v1.0.0                 ║
║  Porta: ${PORT} | API: ${API_URL}              ║
╚════════════════════════════════════════════╝

🎮 GAME CONFIG:
   Energia: ${GAME.MAX_ENERGY} | Custo: ${GAME.ENERGY_COST} | Regen: ${GAME.ENERGY_REGEN}/min
   Win: ${GAME.WIN_PROBABILITY*100}% | Cristal: ${GAME.CRYSTAL_CHANCE*100}% → +${GAME.CRYSTAL_BONUS_HASH} hash + $${GAME.CRYSTAL_BONUS_USD}

🔗 ENDPOINTS:
   GET  /              → Healthcheck
   POST /challenge     → Auth: desafio Phantom
   POST /verify        → Auth: verificar assinatura  
   POST /spin          → Jogar (custa ${GAME.ENERGY_COST} energia)
   POST /reward        → Sacar Hash
   GET  /me            → Dados da sessão
   GET  /stats         → Estatísticas globais
   GET  /*             → Frontend (SPA)

⏰ ${new Date().toISOString()}
`);
});
