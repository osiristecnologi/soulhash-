import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let users = {};

// gerar SoulHash
function generateSoulHash(wallet) {
  return crypto
    .createHash("sha256")
    .update(wallet)
    .digest("hex")
    .slice(0, 12)
    .toUpperCase();
}

// login com wallet
app.post("/login", (req, res) => {
  const { wallet } = req.body;

  if (!users[wallet]) {
    users[wallet] = {
      soulhash: generateSoulHash(wallet),
      luz: 0,
      sombra: 0,
      equilibrio: 0,
    };
  }

  res.json(users[wallet]);
});

// aplicar escolha
app.post("/choice", (req, res) => {
  const { wallet, choice } = req.body;

  let user = users[wallet];

  if (choice === "light") user.luz += 10;
  if (choice === "shadow") user.sombra += 10;
  if (choice === "balance") user.equilibrio += 10;

  res.json(user);
});

app.listen(3000, () => console.log("Server running"));
