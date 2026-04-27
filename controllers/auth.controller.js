import User from "../models/user.model.js";
import crypto from "crypto";
import bs58 from "bs58";

// ===============================
// 🔐 UTILS
// ===============================

function isValidSolanaAddress(addr) {
  try {
    return bs58.decode(addr).length === 32;
  } catch {
    return false;
  }
}

function normalizeWallet(wallet) {
  return wallet.trim();
}

// 🔐 Gera SoulHash FIXO
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
    let { wallet } = req.body;

    // 🔒 validação básica
    if (!wallet) {
      return res.status(400).json({ error: "Wallet obrigatória" });
    }

    wallet = normalizeWallet(wallet);

    if (!isValidSolanaAddress(wallet)) {
      return res.status(400).json({ error: "Wallet inválida" });
    }

    // 🔍 procura usuário
    let user = await User.findOne({ wallet });

    // 🧬 SE NÃO EXISTIR → cria nova alma
    if (!user) {
      user = new User({
        wallet,
        soulhash: generateSoulHash(wallet),
      });

      await user.save();
    }

    // 🔄 atualiza último login
    user.lastLogin = new Date();
    await user.save();

    // 🚀 resposta limpa
    return res.json({
      wallet: user.wallet,
      soulhash: user.soulhash,
      coins: user.coins,
      attrs: user.attrs,
      stats: user.stats,
      createdAt: user.createdAt,
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ error: "Erro no login" });
  }
}
