import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    // 🔑 WALLET
    wallet: {
      type: String,
      required: true,
      unique: true,
      index: true,
      lowercase: true,
      trim: true,
    },

    // 🧠 SOULHASH (ID único do sistema)
    soulhash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // 💰 PAGAMENTOS (txHash + wallet)
    payments: [
      {
        txHash: { type: String, required: true },
        amount: { type: Number, default: 0 },
        createdAt: { type: Date, default: Date.now },
      }
    ],

    // 🎮 ATRIBUTOS
    attrs: {
      luz: { type: Number, default: 0 },
      sombra: { type: Number, default: 0 },
      equilibrio: { type: Number, default: 0 },
      caos: { type: Number, default: 0 },
      empatia: { type: Number, default: 0 },
    },

    // 📊 STATS
    stats: {
      missoes: { type: Number, default: 0 },
      escolhas: { type: Number, default: 0 },
      almas: { type: Number, default: 0 },
      confrontos: { type: Number, default: 0 },
      xp: { type: Number, default: 0 },
    },

    // 🎯 PROGRESSO
    progress: {
      p1: { type: String, default: null },
      p2: { type: String, default: null },
    },

    // 🪙 ECONOMIA
    coins: {
      type: Number,
      default: 100,
    },

    // 🔒 CONTROLE
    lastLogin: {
      type: Date,
      default: Date.now,
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true, // 🔥 createdAt + updatedAt automático
  }
);

// 🔐 EVITA DUPLICAÇÃO DE TXHASH
UserSchema.methods.hasPayment = function (txHash) {
  return this.payments.some(p => p.txHash === txHash);
};

export default mongoose.model("User", UserSchema);
