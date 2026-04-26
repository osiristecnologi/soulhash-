import User from "../models/user.model.js";
import crypto from "crypto";

// 🔐 Gera SoulHash fixo (NUNCA muda depois de criado)
function generateSoulHash(wallet) {
  return crypto
    .createHash("sha256")
    .update(wallet + "-SOULHASH-V1")
    .digest("hex")
    .slice(0, 24)
    .toUpperCase();
}

// ===============================
// 🔑 LOGIN / AUTENTICAÇÃO
// ===============================
export async function login(req, res) {
  try {
    const { wallet } = req.body;

    if (!wallet) {
      return res.status(400).json({ error: "Wallet obrigatória" });
    }

    // 🔍 procura usuário
    let user = await User.findOne({ wallet });

    // 🧬 SE NÃO EXISTIR → cria nova alma
    if (!user) {
      user = await User.create({
        wallet,
        soulhash: generateSoulHash(wallet),

        attrs: {
          luz: 0,
          sombra: 0,
          equilibrio: 0,
          caos: 0,
          empatia: 0,
        },

        stats: {
          missoes: 0,
          escolhas: 0,
          almas: 0,
          confrontos: 0,
          xp: 0,
        },
      });
    }

    // ⚠️ NUNCA gerar soulhash de novo aqui
    return res.json({
      wallet: user.wallet,
      soulhash: user.soulhash,
      createdAt: user.createdAt,
      attrs: user.attrs,
      stats: user.stats,
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro no login" });
  }
}
