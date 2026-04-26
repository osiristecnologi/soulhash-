import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  wallet: {
    type: String,
    unique: true,
    index: true,
    required: true,
  },

  soulhash: {
    type: String,
    unique: true,
    required: true,
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },

  attrs: {
    luz: { type: Number, default: 0 },
    sombra: { type: Number, default: 0 },
    equilibrio: { type: Number, default: 0 },
    caos: { type: Number, default: 0 },
    empatia: { type: Number, default: 0 },
  },

  stats: {
    missoes: { type: Number, default: 0 },
    escolhas: { type: Number, default: 0 },
    almas: { type: Number, default: 0 },
    confrontos: { type: Number, default: 0 },
    xp: { type: Number, default: 0 },
  },

  p1_choice: { type: String, default: null },
  p2_choice: { type: String, default: null },
});

export default mongoose.model("User", UserSchema);
