const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

// TESTE
app.get("/", (req, res) => {
  res.send("API SoulHash online 🚀");
});

// LOGIN → gera hash fixo da wallet
app.post("/login", (req, res) => {
  const { wallet } = req.body;

  const hash = crypto
    .createHash("sha256")
    .update(wallet)
    .digest("hex")
    .slice(0, 12)
    .toUpperCase();

  res.json({ soulhash: hash });
});

// PAGAMENTO → gera hash com assinatura
app.post("/payment", (req, res) => {
  const { signature, wallet } = req.body;

  if (!signature || !wallet) {
    return res.status(400).json({ error: "Dados inválidos" });
  }

  const hash = crypto
    .createHash("sha256")
    .update(wallet + signature)
    .digest("hex")
    .slice(0, 12)
    .toUpperCase();

  res.json({ hash });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor rodando na porta " + PORT);
});
