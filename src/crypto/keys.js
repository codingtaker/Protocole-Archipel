// Gestion des clés Ed25519 avec libsodium

const sodium = require("libsodium-wrappers");

let keyPair = null;

async function initKeys() {
  await sodium.ready;

  keyPair = sodium.crypto_sign_keypair();

  console.log("🔐 Clés Ed25519 générées");
  console.log("Public Key:", Buffer.from(keyPair.publicKey).toString("hex"));
}

function getPublicKey() {
  return Buffer.from(keyPair.publicKey);
}

function sign(dataBuffer) {
  return Buffer.from(
    sodium.crypto_sign_detached(dataBuffer, keyPair.privateKey)
  );
}

module.exports = {
  initKeys,
  getPublicKey,
  sign,
};