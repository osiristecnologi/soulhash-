require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// ═════════ CONFIG ═════════
const GAME = {
  MAX_ENERGY: 10,
  INITIAL_BALANCE: 100,
  WIN: 50,
  LOSE: 10,
  CRYSTAL: 500,
  MAGIC_ENERGY: 20,
  MAGIC_BONUS: 20,
  MIN_WITHDRAW: 20,
  WIN_PROB: 0.30,
  CRYSTAL_PROB: 0.01
};

const CARDS = ["light", "shadow", "chaos", "empathy", "balance"];

// ═════════ MIDDLEWARE ═════════
app.use(express.json({ limit: "10kb" }));
app.use(cors({ origin: "*", credentials: true }));
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

const authLimiter = rateLimit({ windowMs: 60_000, max: 15 });

// ═════════ STORAGE (MEMÓRIA) ═════════
const DB = {
  challenges: new Map(),
  sessions: new Map(),
  walletToHash: new Map(),
  balance: new Map(),
  energy: new Map(),
  stats: new Map(),
};

// ═════════ HELPERS ═════════
const isWallet = (w) => typeof w === "string" && w.length > 10;

const hashWallet = (w) =>
  crypto.createHash("sha256").update(w.toLowerCase()).digest("hex");

const createSession = () => crypto.randomBytes(24).toString("hex");

function requireAuth(req, res, next) {
  const token = req.headers["x-session-token"];
  const wallet = DB.sessions.get(token);

  if (!wallet) {
    return res.status(401).json({ error: "Sessão inválida" });
  }

  req.wallet = wallet;
  req.hash = DB.walletToHash.get(wallet);
  next();
}

function spinEngine() {
  const isCrystal = Math.random() < GAME.CRYSTAL_PROB;
  const isWin = isCrystal || Math.random() < GAME.WIN_PROB;

  const grid = Array.from({ length: 9 }, () =>
    CARDS[Math.floor(Math.random() * CARDS.length)]
  );

  let winPositions = [];

  if (isCrystal) {
    const p = Math.floor(Math.random() * 9);
    grid[p] = "balance";
    winPositions = [p];
  }

  if (isWin && !isCrystal) {
    const a = Math.floor(Math.random() * 9);
    grid[a] = "light";
    winPositions = [a];
  }

  return { grid, isWin, isCrystal, winPositions };
}

// ═════════ ROUTES ═════════

// HEALTH
app.get("/health", (_, res) =>
  res.json({ ok: true, service: "SoulHash API" })
);

// CHALLENGE
app.post("/challenge", authLimiter, (req, res) => {
  const { wallet } = req.body;

  if (!isWallet(wallet)) {
    return res.status(400).json({ error: "Wallet inválida" });
  }

  const message = `SoulHash:${wallet}:${Date.now()}`;
  DB.challenges.set(wallet, { message, used: false });

  res.json({ message });
});

// VERIFY
app.post("/verify", authLimiter, (req, res) => {
  const { wallet } = req.body;

  const challenge = DB.challenges.get(wallet);
  if (!challenge || challenge.used) {
    return res.status(400).json({ error: "Challenge inválido" });
  }

  challenge.used = true;

  const hash = hashWallet(wallet);
  const isNew = !DB.walletToHash.has(wallet);

  DB.walletToHash.set(wallet, hash);

  if (isNew) {
    DB.balance.set(hash, GAME.INITIAL_BALANCE);
    DB.energy.set(hash, GAME.MAX_ENERGY);
    DB.stats.set(hash, { spins: 0, wins: 0, xp: 0 });
  }

  const token = createSession();
  DB.sessions.set(token, wallet);

  res.json({
    sessionToken: token,
    soulhash: hash,
    balance: DB.balance.get(hash),
    energy: GAME.MAX_ENERGY,
    maxEnergy: GAME.MAX_ENERGY,
    stats: DB.stats.get(hash),
    isNew,
  });
});

// SPIN
app.post("/spin", requireAuth, (req, res) => {
  const hash = req.hash;

  const energy = DB.energy.get(hash) || 0;
  if (energy <= 0) {
    return res.status(400).json({ error: "Sem energia" });
  }

  const { grid, isWin, isCrystal, winPositions } = spinEngine();

  DB.energy.set(hash, energy - 1);

  let reward = isCrystal
    ? GAME.CRYSTAL
    : isWin
    ? GAME.WIN
    : GAME.LOSE;

  const balance = (DB.balance.get(hash) || 0) + reward;
  DB.balance.set(hash, balance);

  const stats = DB.stats.get(hash);
  stats.spins++;
  if (isWin || isCrystal) stats.wins++;
  stats.xp += reward;
  DB.stats.set(hash, stats);

  res.json({
    grid,
    isWin,
    isCrystal,
    winPositions,
    reward,
    balance,
    energy: DB.energy.get(hash),
    maxEnergy: GAME.MAX_ENERGY,
    stats
  });
});

// WITHDRAW
app.post("/reward", requireAuth, (req, res) => {
  const { amount } = req.body;
  const hash = req.hash;

  if (!amount || amount < GAME.MIN_WITHDRAW) {
    return res.status(400).json({ error: "Valor mínimo inválido" });
  }

  const bal = DB.balance.get(hash) || 0;

  if (bal < amount) {
    return res.status(400).json({ error: "Saldo insuficiente" });
  }

  const newBal = bal - amount;
  DB.balance.set(hash, newBal);

  res.json({
    success: true,
    amount,
    remainingBalance: newBal,
    tx: crypto.randomBytes(6).toString("hex")
  });
});

// START
app.listen(PORT, () => {
  console.log(`SoulHash API rodando em :${PORT}`);
});
