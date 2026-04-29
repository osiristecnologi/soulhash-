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
// MEMORY STORE (simples)
const challenges = new Map();
const sessions = new Map();
const soulhashStore = new Map();

// cards fake (exemplo)
const CARDS = ["fire", "water", "earth", "air"];

// ─────────────────────────────
// HEALTHCHECK
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "SoulHash API",
    version: "v2",
  });
});

// ─────────────────────────────
// CHALLENGE (wallet login)
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
app.post("/verify", (req, res) => {
  const { wallet, signature } = req.body;

  const entry = challenges.get(wallet);

  if (!entry) {
    return res.status(400).json({ error: "sem challenge" });
  }

  if (entry.used) {
    return res.status(400).json({ error: "challenge já usado" });
  }

  // ⚠️ aqui você pode plugar Solana verify depois
  const valid = Boolean(signature);

  if (!valid) {
    return res.status(401).json({ error: "assinatura inválida" });
  }

  entry.used = true;

  if (!soulhashStore.has(wallet)) {
    soulhashStore.set(wallet, crypto.randomBytes(16).toString("hex"));
  }

  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, wallet);

  res.json({
    sessionToken: token,
    soulhash: soulhashStore.get(wallet),
    level: 1,
    hash_balance: 100,
    energy: 7,
    maxEnergy: 10,
    stats: { xp: 0 },
    dimProgress: 0,
    phasePassed: false,
    ownedCards: {},
    gems: 0,
  });
});

// ─────────────────────────────
// SPIN GAME
app.post("/spin", (req, res) => {
  const token = req.headers["x-session-token"];
  const wallet = sessions.get(token);

  if (!wallet) {
    return res.status(401).json({ error: "sem sessão" });
  }

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
  let winPositions = [];
  let combo = "none";

  for (const [a,b,c] of winLines) {
    if (grid[a] === grid[b] && grid[b] === grid[c]) {
      isWin = true;
      winPositions = [a,b,c];
      combo = "3linha";
      break;
    }
  }

  res.json({
    result: {
      grid,
      isWin,
      winPositions,
      combo,
      reward: isWin ? 50 : 10,
    },
    hash_balance: 100 + (isWin ? 50 : 10),
    energy: 6,
    maxEnergy: 10,
    level: 1,
    dimProgress: isWin ? 200 : 50,
    phasePassed: isWin && Math.random() > 0.5,
    ownedCards: isWin ? { [grid[0]]: 1 } : {},
    stats: { xp: isWin ? 120 : 30 },
  });
});

// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`SoulHash API rodando na porta ${PORT}`);
});
