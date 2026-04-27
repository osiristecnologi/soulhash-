import crypto from "crypto";

function generateSoulHash(wallet) {
  const salt = "SOULHASH-V1-UNIVERSE-SEED";

  return crypto
    .createHash("sha256")
    .update(wallet + salt)
    .digest("hex")
    .slice(0, 24)
    .toUpperCase();
}

function generateSoulID(wallet) {
  const hash = generateSoulHash(wallet);
  return `${wallet}:${hash}`;
}

