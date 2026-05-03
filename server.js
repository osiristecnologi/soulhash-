require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════
app.use(express.json({ limit: "10kb" }));
app.use(cors({ 
  origin: process.env.ALLOWED_ORIGIN || "*", 
  methods: ["GET","POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-session-token"],
  credentials: true
}));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

const authLimiter = rateLimit({ windowMs: 60_000, max: 15 });

// ═══════════════════════════════════════════════════════
// CONSTANTES DO JOGO
// ═══════════════════════════════════════════════════════
const GAME = {
  MAX_ENERGY:         10,
  ENERGY_ON_LOGIN:    10,
  BONUS_WIN_HASH:     50,
  BONUS_LOSE_HASH:    10,
  MAGIC_CARD_ENERGY:  20,
  MAGIC_CARD_HASH:    20,
  INITIAL_BALANCE:    100,
  WITHDRAW_MIN:       20,
  WIN_PROBABILITY:    0.30,
  CRYSTAL_PROBABILITY: 0.01
};

const CARDS = ["light", "shadow", "chaos", "empathy", "balance", "crystal"];

// ═══════════════════════════════════════════════════════
// STORAGE EM MEMÓRIA
// ═══════════════════════════════════════════════════════
const challenges       = new Map();
const sessions         = new Map();
const walletToSoulhash = new Map();
const soulhashToWallet = new Map();
const balances         = new Map();
const energyStore      = new Map();
const statsStore       = new Map();

// ═══════════════════════════════════════════════════════
// UTILITÁRIOS
// ═══════════════════════════════════════════════════════
function isValidWallet(w) {
  return typeof w === "string" && w.length >= 10 && w.length <= 64;
}

function generateSoulHash(wallet) {
  return crypto.createHash("sha256")
    .update(wallet.trim().toLowerCase())
    .digest("hex");
}

function requireSession(req, res, next) {
  const token  = req.headers["x-session-token"];
  const wallet = sessions.get(token);
  if (!wallet) return res.status(401).json({ error: "Sessão inválida ou expirada." });
  req.wallet   = wallet;
  req.soulhash = walletToSoulhash.get(wallet);
  next();
}

function calcLevel(xp) {
  return Math.floor(xp / 1000) + 1;
}

// ═══════════════════════════════════════════════════════
// LÓGICA DO SPIN
// ═══════════════════════════════════════════════════════
function computeSpin() {
  const isCrystal = Math.random() < GAME.CRYSTAL_PROBABILITY;
  const isWin = isCrystal || Math.random() < GAME.WIN_PROBABILITY;

  const grid = Array.from({ length: 9 }, () => {
    if (isCrystal && Math.random() < 0.1) return "crystal";
    return CARDS[Math.floor(Math.random() * (CARDS.length - 1))];
  });

  const WIN_LINES = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  let winPositions = [];
  let combo = "none";
  let magicCenter = false;

  if (isCrystal) {
    const crystalPos = Math.floor(Math.random() * 9);
    grid[crystalPos] = "crystal";
    winPositions = [crystalPos];
    combo = "crystal";
  } else if (isWin) {
    const lineIdx = Math.floor(Math.random() * WIN_LINES.length);
    const [a, b, c] = WIN_LINES[lineIdx];
    const winner = CARDS[Math.floor(Math.random() * (CARDS.length - 1))];
    grid[a] = grid[b] = grid[c] = winner;
    winPositions = [a, b, c];
    combo = "3linha";
  }

  if (grid[4] === "balance") magicCenter = true;

  return { grid, isWin, isCrystal, winPositions, combo, magicCenter };
}

// ═══════════════════════════════════════════════════════
// ROTAS
// ═══════════════════════════════════════════════════════

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "SoulHash API", version: "v1" });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// POST /challenge
app.post("/challenge", authLimiter, (req, res) => {
  const { wallet } = req.body;
  if (!isValidWallet(wallet)) {
    return res.status(400).json({ error: "Wallet inválida." });
  }

  const message = `SoulHash:${wallet}:${Date.now()}`;
  challenges.set(wallet, { message, used: false });

  res.json({ message });
});

// POST /verify
app.post("/verify", authLimiter, async (req, res) => {
  const { wallet, signature } = req.body;

  if (!isValidWallet(wallet)) {
    return res.status(400).json({ error: "Wallet inválida." });
  }
  if (!signature) {
    return res.status(401).json({ error: "Assinatura ausente." });
  }

  const entry = challenges.get(wallet);
  if (!entry) {
    return res.status(400).json({ error: "Sem challenge. Chame /challenge primeiro." });
  }
  if (entry.used) {
    return res.status(400).json({ error: "Challenge já utilizado." });
  }

  entry.used = true;

  const soulhash = generateSoulHash(wallet);
  const isNew = !walletToSoulhash.has(wallet);

  walletToSoulhash.set(wallet, soulhash);
  soulhashToWallet.set(soulhash, wallet);

  if (isNew) {
    balances.set(soulhash, GAME.INITIAL_BALANCE);
    statsStore.set(soulhash, { spins: 0, wins: 0, xp: 0 });
  }

  energyStore.set(soulhash, GAME.MAX_ENERGY);

  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, wallet);

  res.json({
    sessionToken: token,
    soulhash,
    isNew,
    balance: balances.get(soulhash),
    energy: GAME.MAX_ENERGY,
    maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(statsStore.get(soulhash)?.xp ?? 0),
    stats: statsStore.get(soulhash),
  });
});

// POST /spin
app.post("/spin", requireSession, (req, res) => {
  const { soulhash } = req;

  const currentEnergy = energyStore.get(soulhash) ?? 0;
  if (currentEnergy <= 0) {
    return res.status(400).json({ error: "Sem energia. Aguarde recarga." });
  }

  const { grid, isWin, isCrystal, winPositions, combo, magicCenter } = computeSpin();

  const newEnergy = Math.max(0, currentEnergy - 1);
  energyStore.set(soulhash, newEnergy);

  let reward = 0;
  if (isCrystal) {
    reward = 500;
  } else if (isWin) {
    reward = GAME.BONUS_WIN_HASH;
  } else {
    reward = GAME.BONUS_LOSE_HASH;
  }

  if (magicCenter) {
    reward += GAME.MAGIC_CARD_HASH;
    const newEnergyWithBonus = Math.min(GAME.MAX_ENERGY, newEnergy + GAME.MAGIC_CARD_ENERGY);
    energyStore.set(soulhash, newEnergyWithBonus);
  }

  const currentBalance = balances.get(soulhash) ?? 0;
  const newBalance = currentBalance + reward;
  balances.set(soulhash, newBalance);

  const stats = statsStore.get(soulhash) ?? { spins: 0, wins: 0, xp: 0 };
  stats.spins++;
  if (isWin || isCrystal) stats.wins++;
  stats.xp += isCrystal ? 100 : isWin ? 40 : 10;
  statsStore.set(soulhash, stats);

  res.json({
    grid,
    isWin: isWin || isCrystal,
    isCrystal,
    winPositions,
    combo: isCrystal ? "crystal" : combo,
    reward,
    magicCenter,
    balance: newBalance,
    energy: energyStore.get(soulhash),
    maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp),
    stats,
  });
});

// POST /reward
app.post("/reward", requireSession, (req, res) => {
  const { soulhash, wallet } = req;
  const { amount } = req.body;

  if (!amount || isNaN(amount) || amount < GAME.WITHDRAW_MIN) {
    return res.status(400).json({
      error: `Valor mínimo de saque é ${GAME.WITHDRAW_MIN} Hash.`,
    });
  }

  const balance = balances.get(soulhash) ?? 0;
  if (balance < amount) {
    return res.status(400).json({ error: "Saldo insuficiente.", balance });
  }

  const newBalance = balance - amount;
  balances.set(soulhash, newBalance);

  const simulatedTx = `SIM_${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  console.log(`[REWARD] ${amount} Hash → ${wallet} | tx: ${simulatedTx}`);

  res.json({
    success: true,
    paidTo: wallet,
    amount,
    remainingBalance: newBalance,
    txSimulated: simulatedTx,
  });
});

// GET /me
app.get("/me", requireSession, (req, res) => {
  const { soulhash, wallet } = req;
  const stats = statsStore.get(soulhash) ?? { spins: 0, wins: 0, xp: 0 };
  res.json({
    soulhash,
    wallet: wallet.slice(0,6) + "..." + wallet.slice(-4),
    balance: balances.get(soulhash) ?? 0,
    energy: energyStore.get(soulhash) ?? 0,
    maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp),
    stats,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: `Rota ${req.method} ${req.path} não encontrada.` });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Erro interno do servidor." });
});

// ═══════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n╔════════════════════════════════════════════╗`);
  console.log(`║  SoulHash API — Porta ${PORT}                  ║`);
  console.log(`╚════════════════════════════════════════════╝`);
  console.log(`  Servidor rodando em http://localhost:${PORT}`);
  console.log(`  Health check: http://localhost:${PORT}/health\n`);
});
