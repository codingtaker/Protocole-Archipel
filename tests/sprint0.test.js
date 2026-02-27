
const assert = require("assert");
const crypto = require("crypto");
const sodium = require("libsodium-wrappers");

const { initKeys, getPublicKey } = require("../src/crypto/keys");
const { buildPacket, parsePacket, extractPackets } = require("../src/protocol/packet");

const HMAC_KEY = "archipel-secret-temp";

function verifyHmac(buffer) {
  const body = buffer.slice(0, buffer.length - 32);
  const receivedHmac = buffer.slice(buffer.length - 32);

  const computedHmac = crypto
    .createHmac("sha256", HMAC_KEY)
    .update(body)
    .digest();

  return crypto.timingSafeEqual(receivedHmac, computedHmac);
}

async function runTests() {
  console.log("🧪 Lancement des tests Sprint 0...\n");

  await initKeys();

  // ✅ Test 1 — clé publique longueur correcte
    const pubKey = getPublicKey();
    assert.strictEqual(pubKey.length, 32, "❌ Clé publique doit faire 32 bytes");
    console.log("✔ Clé publique valide (32 bytes)");

  // ✅ Test 2 — Construction paquet
    await sodium.ready;

    const payload = Buffer.from("Hello Archipel");
    const packet = buildPacket(0x01, payload, Buffer.from("Signed"));

    assert.ok(packet.length > 73, "❌ Packet trop court");
    console.log("✔ Packet construit");

  // ✅ Test 3 — Parsing correct
  const parsed = parsePacket(packet);

  assert.strictEqual(parsed.magic, "ARCH", "❌ MAGIC incorrect");
  assert.strictEqual(parsed.type, 0x01, "❌ TYPE incorrect");
  assert.strictEqual(parsed.nodeId.length, 32, "❌ NODE_ID incorrect");
  assert.strictEqual(parsed.payloadLen, payload.length, "❌ PAYLOAD_LEN incorrect");
  assert.strictEqual(parsed.payload.toString(), "Hello Archipel", "❌ Payload incorrect");

  console.log("✔ Header conforme à la spécification");

  // ✅ Test 4 — Intégrité HMAC valide
  const isValid = verifyHmac(packet);
  assert.strictEqual(isValid, true, "❌ HMAC invalide");

  console.log("✔ HMAC valide");

    // ✅ Test 5 — Détection corruption
    const tampered = Buffer.from(packet);
    tampered[10] = 0x00;

    const tamperedValid = verifyHmac(tampered);
    assert.strictEqual(tamperedValid, false, "❌ Corruption non détectée");

    console.log("✔ Corruption détectée correctement");

    // Test 6 — Fragmentation TCP
    const payload2 = Buffer.from("Boundary Test");
    const packet2 = buildPacket(0x01, payload2);

    // On coupe le packet en deux
    const half = Math.floor(packet2.length / 2);
    const part1 = packet2.slice(0, half);
    const part2 = packet2.slice(half);

    let buffer = Buffer.concat([part1]);
    let result1 = extractPackets(buffer);
    assert.strictEqual(result1.packets.length, 0, "❌ Fragment ne devrait pas parser");

    buffer = Buffer.concat([result1.remaining, part2]);

    let result2 = extractPackets(buffer);
    assert.strictEqual(result2.packets.length, 1, "❌ Packet complet attendu");

    console.log("✔ Gestion fragmentation TCP OK");

    // Test 7 — Paquets multiples dans un même buffer
    const packetA = buildPacket(0x01, Buffer.from("A"));
    const packetB = buildPacket(0x01, Buffer.from("B"));

    const combined = Buffer.concat([packetA, packetB]);
    const result3 = extractPackets(combined);

    assert.strictEqual(result3.packets.length, 2, "❌ Doit détecter 2 packets");
    console.log("✔ Gestion packets collés OK");

    // Test 8 — Mauvaise longueur (attaque)
    const corrupted = Buffer.from(packetA);

    // On falsifie la longueur payload
    corrupted.writeUInt32BE(999999, 37);

    const result4 = extractPackets(corrupted);
    assert.strictEqual(result4.packets.length, 0, "❌ Longueur invalide doit être rejetée");

    console.log("✔ Protection longueur invalide OK");

    // Test 9 — Signature Ed25519
    const body = packet.slice(0, packet.length - 96); 

    const isValidSig = sodium.crypto_sign_verify_detached(
    parsed.signature,
    body,
    parsed.nodeId
    );

    assert.strictEqual(isValidSig, true, "❌ Signature invalide");
    console.log("✔ Signature Ed25519 valide");

  console.log("\n🎉 Tous les tests Sprint 0 sont PASSÉS !");
}

runTests().catch(err => {
  console.error("\n❌ Échec des tests :", err.message);
  process.exit(1);
});