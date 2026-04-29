  const valid = verifySignature(wallet, entry.message, signature);

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
    gems: 0,
  });
});

// ─────────────────────────────
// SPIN (JOGO)
// ─────────────────────────────
app.post("/spin", (req, res) => {
  const token = req.headers["x-session-token"];

  const wallet = sessions.get(token);

  if (!wallet) {
    return res.status(401).json({ error: "sem sessão" });
  }

  const grid = Array.from({ length: 9 }, () =>
    CARDS[Math.floor(Math.random() * CARDS.length)]
  );

  // checar vitória simples (3 iguais em linha)
  const winLines = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  let isWin = false;
  let winPositions = [];
  let combo = "none";

  for (const line of winLines) {
    const [a,b,c] = line;
    if (grid[a] === grid[b] && grid[b] === grid[c]) {
      isWin = true;
      winPositions = line;
      combo = "3linha";
      break;
    }
  }

  let hash_balance = 100 + (isWin ? 50 : 10);
  let energy = 6;
  let level = 1;
  let dimProgress = isWin ? 200 : 50;

  const ownedCards = {};
  if (isWin) ownedCards[grid[0]] = 1;

  res.json({
    result: {
      grid,
      isWin,
      winPositions,
      combo,
      reward: isWin ? 50 : 10,
    },
    hash_balance,
    energy,
    maxEnergy: 10,
    level,
    dimProgress,
    phasePassed: isWin && Math.random() > 0.5,
    ownedCards,
    stats: { xp: isWin ? 120 : 30 },
  });
});

// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`SoulHash backend rodando na porta ${PORT}`);
});

