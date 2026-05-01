require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────
// MIDDLEWARE
// ─────────────────────────────
app.use(express.json());
app.use(cors());
app.use(helmet());

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
  })
);

// ─────────────────────────────
// MEMORY STORE (MAPS)
// ─────────────────────────────
const challenges = new Map();          // wallet → challenge
const sessions = new Map();            // token → wallet

const walletToSoulhash = new Map();    // wallet → soulhash
const soulhashToWallet = new Map();    // soulhash → wallet

const balances = new Map();            // soulhash → balance

// ─────────────────────────────
// GAME CARDS
// ─────────────────────────────
const CARDS = ["fire", "water", "earth", "air"];

// ─────────────────────────────
// HEALTHCHECK
// ─────────────────────────────
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "SoulHash API",
    version: "v4-payments",
  });
});

// ─────────────────────────────
// CHALLENGE LOGIN
// ─────────────────────────────
app.post("/challenge", (req, res) => {
  const { wallet } = req.body;

  if (!wallet || wallet.length < 10) {
    return res.status(400).json({ error: "Wallet inválida" });
  }

  const message = `SoulHash:${wallet}:${Date.now()}`;

  challenges.set(wallet, {
    message,
    used: false,
  });

  res.json({ message });
});

// ─────────────────────────────
// VERIFY LOGIN
// ─────────────────────────────
app.post("/verify", (req, res) => {
  const { wallet, signature } = req.body;

  const entry = challenges.get(wallet);

  if (!entry) {
    return res.status(400).json({ error: "sem challenge" });
  }

  if (entry.used) {
    return res.status(400).json({ error: "challenge já usado" });
  }

  if (!signature) {
    return res.status(401).json({ error: "assinatura inválida" });
  }

  entry.used = true;

  // ─────────────────────────────
  // SOULHASH
  // ─────────────────────────────
  const soulhash = crypto
    .createHash("sha256")
    .update(wallet.trim().toLowerCase())
    .digest("hex");

  // MAP RELATIONS
  walletToSoulhash.set(wallet, soulhash);
  soulhashToWallet.set(soulhash, wallet);

  // INIT BALANCE
  balances.set(soulhash, 100);

  // SESSION
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, wallet);

  res.json({
    sessionToken: token,
    soulhash,
    balance: balances.get(soulhash),
    level: 1,
    energy: 7,
    maxEnergy: 10,
  });
});

// ─────────────────────────────
// SPIN GAME
// ─────────────────────────────
app.post("/spin", (req, res) => {
  const token = req.headers["x-session-token"];
  const wallet = sessions.get(token);

  if (!wallet) {
    return res.status(401).json({ error: "sem sessão" });
  }

  const soulhash = walletToSoulhash.get(wallet);

  const grid = Array.from(
    { length: 9 },
    () => CARDS[Math.floor(Math.random() * CARDS.length)]
  );

  const winLines = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  let isWin = false;

  for (const [a,b,c] of winLines) {
    if (grid[a] === grid[b] && grid[b] === grid[c]) {
      isWin = true;
      break;
    }
  }

  const reward = isWin ? 50 : 10;

  const currentBalance = balances.get(soulhash) || 0;
  balances.set(soulhash, currentBalance + reward);

  res.json({
    grid,
    isWin,
    reward,
    balance: balances.get(soulhash),
  });
});

// ─────────────────────────────
// 💰 REWARD / PAYMENT SYSTEM
// ─────────────────────────────
app.post("/reward", (req, res) => {
  const { soulhash, amount } = req.body;

  const wallet = soulhashToWallet.get(soulhash);

  if (!wallet) {
    return res.status(404).json({ error: "jogador não encontrado" });
  }

  const balance = balances.get(soulhash) || 0;

  if (balance < amount) {
    return res.status(400).json({ error: "saldo insuficiente" });
  }

  balances.set(soulhash, balance - amount);

  // SIMULAÇÃO DE PAGAMENTO ON-CHAIN
  console.log(`💸 Pagando ${amount} para wallet: ${wallet}`);

  res.json({
    success: true,
    paidTo: wallet,
    amount,
    remainingBalance: balances.get(soulhash),
  });
});

// ─────────────────────────────
// START SERVER
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`SoulHash API rodando na porta ${PORT}`);
});
