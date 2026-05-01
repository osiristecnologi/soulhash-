require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════
app.use(express.json({ limit: "10kb" }));
app.use(cors());
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

const authLimiter = rateLimit({ windowMs: 60_000, max: 15 });

// ═══════════════════════════════════════
// GAME CONFIG
// ═══════════════════════════════════════
const GAME = {
  MAX_ENERGY: 10,
  INITIAL_BALANCE: 100,
  WIN_PROBABILITY: 0.30,
  BONUS_WIN: 50,
  BONUS_LOSE: 10,
  MAGIC_BONUS: 20,
  MAGIC_ENERGY: 2,
  CHALLENGE_TTL: 1000 * 60 * 3, // 3 min
  SESSION_TTL: 1000 * 60 * 60 * 2 // 2h
};

const CARDS = ["fire", "water", "earth", "air", "magic"];

// ═══════════════════════════════════════
// MEMORY STORE (trocar por Redis depois)
// ═══════════════════════════════════════
const challenges = new Map(); // wallet → {msg, exp}
const sessions   = new Map(); // token → {wallet, exp}

const walletToSoul = new Map();
const soulToWallet = new Map();

const balance = new Map();
const energy  = new Map();
const stats   = new Map();
const lastSpin = new Map();

// ═══════════════════════════════════════
// UTILS
// ═══════════════════════════════════════
function now() { return Date.now(); }

function isValidWallet(w) {
  return typeof w === "string" && w.length > 10;
}

function generateSoul(wallet) {
  return crypto.createHash("sha256")
    .update(wallet.toLowerCase())
    .digest("hex");
}

// sessão middleware
function requireSession(req, res, next) {
  const token = req.headers["x-session-token"];
  const session = sessions.get(token);

  if (!session) return res.status(401).json({ error: "Sessão inválida" });
  if (session.exp < now()) {
    sessions.delete(token);
    return res.status(401).json({ error: "Sessão expirada" });
  }

  req.wallet = session.wallet;
  req.soul   = walletToSoul.get(session.wallet);
  next();
}

// limpeza automática leve
setInterval(() => {
  const t = now();

  for (const [k,v] of challenges)
    if (v.exp < t) challenges.delete(k);

  for (const [k,v] of sessions)
    if (v.exp < t) sessions.delete(k);

}, 60_000);

// ═══════════════════════════════════════
// CHALLENGE
// ═══════════════════════════════════════
app.post("/challenge", authLimiter, (req,res)=>{
  const { wallet } = req.body;
  if (!isValidWallet(wallet))
    return res.status(400).json({ error: "wallet inválida" });

  const msg = `SoulHash:${wallet}:${crypto.randomUUID()}`;

  challenges.set(wallet, {
    msg,
    exp: now() + GAME.CHALLENGE_TTL
  });

  res.json({ message: msg });
});

// ═══════════════════════════════════════
// VERIFY (estrutura pronta Web3 real)
// ═══════════════════════════════════════
app.post("/verify", authLimiter, (req,res)=>{
  const { wallet, signature } = req.body;

  const ch = challenges.get(wallet);
  if (!ch) return res.status(400).json({ error: "sem challenge" });
  if (ch.exp < now()) return res.status(400).json({ error: "challenge expirado" });

  // ⚠️ aqui é onde você integra MetaMask / Phantom
  // (placeholder por enquanto)
  const isValidSignature = true;

  if (!isValidSignature)
    return res.status(401).json({ error: "assinatura inválida" });

  const soul = generateSoul(wallet);
  const isNew = !walletToSoul.has(wallet);

  walletToSoul.set(wallet, soul);
  soulToWallet.set(soul, wallet);

  if (isNew) {
    balance.set(soul, GAME.INITIAL_BALANCE);
    stats.set(soul, { spins: 0, wins: 0, xp: 0 });
  }

  energy.set(soul, GAME.MAX_ENERGY);

  const token = crypto.randomBytes(24).toString("hex");

  sessions.set(token, {
    wallet,
    exp: now() + GAME.SESSION_TTL
  });

  res.json({
    sessionToken: token,
    soul,
    balance: balance.get(soul),
    energy: GAME.MAX_ENERGY,
    maxEnergy: GAME.MAX_ENERGY,
    stats: stats.get(soul)
  });
});

// ═══════════════════════════════════════
// SPIN (mais seguro)
// ═══════════════════════════════════════
function spin() {
  const isWin = crypto.randomInt(0,100) < (GAME.WIN_PROBABILITY * 100);

  const grid = Array.from({length:9}, () =>
    CARDS[crypto.randomInt(0, CARDS.length)]
  );

  if (isWin) {
    const win = CARDS[crypto.randomInt(0, CARDS.length)];
    const line = [0,1,2];

    for (const i of line) grid[i] = win;

    return { grid, isWin, win };
  }

  return { grid, isWin, win: null };
}

// anti spam spin
function canSpin(soul) {
  const last = lastSpin.get(soul) || 0;
  return now() - last > 1500;
}

// ═══════════════════════════════════════
// SPIN ROUTE
// ═══════════════════════════════════════
app.post("/spin", requireSession, (req,res)=>{
  const soul = req.soul;

  if (!canSpin(soul))
    return res.status(429).json({ error: "muito rápido" });

  let e = energy.get(soul) ?? 0;
  if (e <= 0)
    return res.status(400).json({ error: "sem energia" });

  const result = spin();

  energy.set(soul, e - 1);
  lastSpin.set(soul, now());

  let reward = result.isWin ? GAME.BONUS_WIN : GAME.BONUS_LOSE;

  const b = balance.get(soul) || 0;
  balance.set(soul, b + reward);

  const st = stats.get(soul);
  st.spins++;
  if (result.isWin) st.wins++;
  st.xp += result.isWin ? 40 : 10;

  stats.set(soul, st);

  res.json({
    ...result,
    reward,
    balance: balance.get(soul),
    energy: energy.get(soul),
    stats: st
  });
});

// ═══════════════════════════════════════
// ME
// ═══════════════════════════════════════
app.get("/me", requireSession, (req,res)=>{
  const soul = req.soul;
  const st = stats.get(soul);

  res.json({
    soul,
    balance: balance.get(soul),
    energy: energy.get(soul),
    stats: st
  });
});

// ═══════════════════════════════════════
// START
// ═══════════════════════════════════════
app.listen(PORT, ()=>{
  console.log("SoulHash API v6 rodando na porta", PORT);
});
