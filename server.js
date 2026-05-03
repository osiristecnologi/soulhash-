require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════════════
app.use(express.json({ limit: "10kb" }));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || "*", methods: ["GET","POST"] }));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

const authLimiter = rateLimit({ windowMs: 60_000, max: 15 });

// ═══════════════════════════════════════════════════════
//  CONSTANTES DO JOGO
// ═══════════════════════════════════════════════════════
const GAME = {
  MAX_ENERGY:         10,
  ENERGY_ON_LOGIN:    10,
  INITIAL_BALANCE:    100,
  WITHDRAW_MIN:       20,
  WIN_PROBABILITY:    0.30,   // 30% chance de vitória
  CRYSTAL_PROBABILITY: 0.01,  // 1% chance de cristal
  WIN_REWARD:         20,     // +20 Hash na vitória
  CRYSTAL_REWARD:     500,    // +500 Hash no cristal
  CRYSTAL_CASH:       20,     // $20 no cristal
  SPIN_COST:          10,     // -10 Hash por jogada
};

// Cartas disponíveis
const CARDS = ["fire", "water", "earth", "air", "crystal"];

// ═══════════════════════════════════════════════════════
//  STORAGE EM MEMÓRIA
// ═══════════════════════════════════════════════════════
const challenges       = new Map();
const sessions         = new Map();
const walletToSoulhash = new Map();
const soulhashToWallet = new Map();
const balances         = new Map();
const energyStore      = new Map();
const statsStore       = new Map();
const cashStore        = new Map(); // Armazena $ para cada usuário

// ═══════════════════════════════════════════════════════
//  UTILITÁRIOS
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

// ═══════════════════════════════════════════════════════
//  LÓGICA DO SPIN (somente servidor)
// ═══════════════════════════════════════════════════════
function computeSpin() {
  const rand = Math.random();
  const isCrystal = rand < GAME.CRYSTAL_PROBABILITY; // 1%
  const isWin = isCrystal || (rand < (GAME.CRYSTAL_PROBABILITY + GAME.WIN_PROBABILITY)); // 31% total

  // Gera grid 3×3
  const grid = Array.from({ length: 9 }, () =>
    CARDS[Math.floor(Math.random() * CARDS.length)]
  );

  const WIN_LINES = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  let winPositions = [];
  let combo        = "none";

  if (isCrystal) {
    // Cristal aparece em posição aleatória
    const crystalPos = Math.floor(Math.random() * 9);
    grid[crystalPos] = "crystal";
    winPositions = [crystalPos];
    combo = "crystal";
  } else if (isWin) {
    // Força uma linha vencedora
    const lineIdx = Math.floor(Math.random() * WIN_LINES.length);
    const [a, b, c] = WIN_LINES[lineIdx];
    const winner = CARDS[Math.floor(Math.random() * (CARDS.length - 1))]; // Não inclui crystal
    grid[a] = grid[b] = grid[c] = winner;
    winPositions = [a, b, c];
    combo = "3linha";
  } else {
    // Derrota: garante que não há linha vencedora
    let tries = 0;
    while (tries++ < 50) {
      let hasWin = false;
      for (const [a,b,c] of WIN_LINES) {
        if (grid[a] === grid[b] && grid[b] === grid[c]) { hasWin = true; break; }
      }
      if (!hasWin) break;
      for (let i = 0; i < 9; i++) grid[i] = CARDS[Math.floor(Math.random() * CARDS.length)];
    }
  }

  return { grid, isWin, isCrystal, winPositions, combo };
}

// ═══════════════════════════════════════════════════════
//  ROTAS
// ═══════════════════════════════════════════════════════

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "SoulHash API", version: "v6" });
});

// ── POST /challenge ──────────────────────────────────
app.post("/challenge", authLimiter, (req, res) => {
  const { wallet } = req.body;
  if (!isValidWallet(wallet)) return res.status(400).json({ error: "Wallet inválida." });

  const message = `SoulHash:${wallet}:${Date.now()}`;
  challenges.set(wallet, { message, used: false });

  res.json({ message });
});

// ── POST /verify ─────────────────────────────────────
app.post("/verify", authLimiter, (req, res) => {
  const { wallet, signature } = req.body;

  if (!isValidWallet(wallet)) return res.status(400).json({ error: "Wallet inválida." });
  if (!signature)             return res.status(401).json({ error: "Assinatura ausente." });

  const entry = challenges.get(wallet);
  if (!entry)      return res.status(400).json({ error: "Sem challenge. Chame /challenge." });
  if (entry.used)  return res.status(400).json({ error: "Challenge já utilizado." });

  entry.used = true;

  const soulhash = generateSoulHash(wallet);
  const isNew    = !walletToSoulhash.has(wallet);

  walletToSoulhash.set(wallet, soulhash);
  soulhashToWallet.set(soulhash, wallet);

  if (isNew) {
    balances.set(soulhash, GAME.INITIAL_BALANCE);
    energyStore.set(soulhash, GAME.MAX_ENERGY);
    statsStore.set(soulhash, { spins: 0, wins: 0, xp: 0 });
    cashStore.set(soulhash, 0); // Inicia com $0
  }

  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, wallet);

  res.json({
    sessionToken: token,
    soulhash,
    isNew,
    balance:    balances.get(soulhash),
    energy:     GAME.MAX_ENERGY,
    maxEnergy:  GAME.MAX_ENERGY,
    level:      calcLevel(statsStore.get(soulhash)?.xp ?? 0),
    stats:      statsStore.get(soulhash),
  });
});

// ── POST /spin ───────────────────────────────────────
app.post("/spin", requireSession, (req, res) => {
  const { soulhash } = req;

  // Verifica saldo (backend é fonte de verdade)
  const currentBalance = balances.get(soulhash) ?? 0;
  if (currentBalance < GAME.SPIN_COST) {
    return res.status(400).json({ error: "Hash insuficiente." });
  }

  // Calcula resultado (somente servidor)
  const { grid, isWin, isCrystal, winPositions, combo } = computeSpin();

  // Calcula recompensa
  let reward = 0;
  let cashReward = 0;

  if (isCrystal) {
    reward = GAME.CRYSTAL_REWARD;
    cashReward = GAME.CRYSTAL_CASH;
  } else if (isWin) {
    reward = GAME.WIN_REWARD;
  }

  // Debita custo da jogada
  const newBalance = currentBalance - GAME.SPIN_COST + reward;
  balances.set(soulhash, newBalance);

  // Adiciona cash se for cristal
  if (cashReward > 0) {
    const currentCash = cashStore.get(soulhash) ?? 0;
    cashStore.set(soulhash, currentCash + cashReward);
  }

  // Debita 1 de energia
  const currentEnergy = energyStore.get(soulhash) ?? 0;
  const newEnergy = Math.max(0, currentEnergy - 1);
  energyStore.set(soulhash, newEnergy);

  // Atualiza stats
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
    combo,
    reward: isCrystal ? reward : (isWin ? reward : 0),
    cashReward,
    balance: newBalance,
    energy: newEnergy,
    maxEnergy: GAME.MAX_ENERGY,
    level: calcLevel(stats.xp),
    stats,
  });
});

// ── POST /reward ─────────────────────────────────────
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
    return res.status(400).json({
      error: "Saldo insuficiente.",
      balance,
    });
  }

  const newBalance = balance - amount;
  balances.set(soulhash, newBalance);

  const simulatedTx = `SIM_${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
  console.log(`[REWARD] ${amount} Hash → ${wallet} | tx: ${simulatedTx}`);

  res.json({
    success:          true,
    paidTo:           wallet,
    amount,
    remainingBalance: newBalance,
    txSimulated:      simulatedTx,
  });
});

// ── GET /me ────────────────────────────────────────
app.get("/me", requireSession, (req, res) => {
  const { soulhash, wallet } = req;
  const stats = statsStore.get(soulhash) ?? { spins: 0, wins: 0, xp: 0 };
  res.json({
    soulhash,
    wallet:   wallet.slice(0,6) + "..." + wallet.slice(-4),
    balance:  balances.get(soulhash) ?? 0,
    cash:     cashStore.get(soulhash) ?? 0,
    energy:   energyStore.get(soulhash) ?? 0,
    maxEnergy: GAME.MAX_ENERGY,
    level:    calcLevel(stats.xp),
    stats,
  });
});

// ═══════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════
function calcLevel(xp) {
  return Math.floor(xp / 1000) + 1;
}

// 404
app.use((req, res) => {
  res.status(404).json({ error: `Rota ${req.method} ${req.path} não encontrada.` });
});

// ═══════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════╗`);
  console.log(`║  SoulHash API v6  —  Porta ${PORT}             ║`);
  console.log(`╚════════════════════════════════════════════╝`);
  console.log(`  GET  /`);
  console.log(`  POST /challenge  → desafio para Phantom`);
  console.log(`  POST /verify     → autentica + 100 Hash`);
  console.log(`  POST /spin       → gira cartas (-10 Hash)`);
  console.log(`  POST /reward     → saque de hash`);
  console.log(`  GET  /me         → estado da sessão\n`);
});
