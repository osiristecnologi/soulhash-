import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "x-session-token"]
}));

// ─────────────────────────────
// MEMORY STORE (simples)
const challenges = new Map();
const sessions = new Map();
const soulhashStore = new Map();

// exemplo cards (ajuste se já tiver)
const CARDS = ["A", "B", "C", "D"];

// ─────────────────────────────
// CHALLENGE
// ─────────────────────────────
app.post("/challenge", (req, res) => {
  const { wallet } = req.body;

  if (!wallet || typeof wallet !== "string") {
    return res.status(400).json({ error: "wallet inválida" });
  }

  const message = `SoulHash login: ${crypto.randomBytes(12).toString("hex")}`;

  challenges.set(wallet, {
    message,
    used: false
  });

  res.json({ wallet, message });
});

// ─────────────────────────────
// LOGIN (verifica assinatura)
// ─────────────────────────────
app.post("/login", (req, res) => {
  const { wallet, signature, message } = req.body;

  if (!wallet || !signature || !message) {
    return res.status(400).json({ error: "dados incompletos" });
  }

  const entry = challenges.get(wallet);

  if (!entry || entry.used || entry.message !== message) {
    return res.status(401).json({ error: "challenge inválido" });
  }

  // ⚠️ aqui você já tinha verifySignature
  const valid = verifySignature(wallet, message, signature);

  if (!valid) {
    return res.status(401).json({ error: "assinatura inválida" });
  }

  entry.used = true;

  if (!soulhashStore.has(wallet)) {
    soulhashStore.set(wallet, generateSoulHash(wallet));
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
    gems: 0
  });
});

// ─────────────────────────────
// SPIN
// ─────────────────────────────
app.post("/spin", (req, res) => {
  const token = req.headers["x-session-token"];

  if (!token || typeof token !== "string") {
    return res.status(401).json({ error: "token inválido" });
  }

  const wallet = sessions.get(token);

  if (!wallet) {
    return res.status(401).json({ error: "sem sessão" });
  }

  const grid = Array.from({ length: 9 }, () =>
    CARDS[Math.floor(Math.random() * CARDS.length)]
  );

  const winLines = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  let isWin = false;
  let winPositions = [];

  for (const [a,b,c] of winLines) {
    if (grid[a] === grid[b] && grid[b] === grid[c]) {
      isWin = true;
      winPositions = [a,b,c];
      break;
    }
  }

  res.json({
    result: {
      grid,
      isWin,
      winPositions,
      reward: isWin ? 50 : 10
    },
    hash_balance: isWin ? 150 : 110,
    energy: 6,
    maxEnergy: 10,
    level: 1,
    dimProgress: isWin ? 200 : 50,
    phasePassed: isWin && Math.random() > 0.5,
    ownedCards: isWin ? { [grid[0]]: 1 } : {},
    stats: { xp: isWin ? 120 : 30 }
  });
});

// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`SoulHash API rodando na porta ${PORT}`);
});

