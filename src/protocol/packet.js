const crypto = require("crypto");
const { MAGIC, HMAC_SECRET } = require("../config");
const { getPublicKey, sign } = require("../crypto/keys");
const sodium = require("libsodium-wrappers");


async function verifySignature(packet) {
  await sodium.ready;

  const body = Buffer.concat([
    Buffer.from("ARCH"),
    Buffer.from([packet.type]),
    packet.nodeId,
    (function(){ const b=Buffer.alloc(4); b.writeUInt32BE(packet.payloadLen,0); return b })(),
    packet.payload
  ]);

  return sodium.crypto_sign_verify_detached(
    packet.signature,
    body,
    packet.nodeId
  );
}

function buildPacket(type, payloadBuffer) {
  if (!Buffer.isBuffer(payloadBuffer)) {
    throw new Error("Payload must be a Buffer");
  }

  const nodeId = getPublicKey();

  const payloadLen = Buffer.alloc(4);
  payloadLen.writeUInt32BE(payloadBuffer.length, 0);

  const header = Buffer.concat([
    MAGIC,
    Buffer.from([type]),
    nodeId,
    payloadLen
  ]);

  const body = Buffer.concat([header, payloadBuffer]);

  // 🔐 Signature Ed25519 sur HEADER + PAYLOAD
  const signature = sign(body); // 64 bytes

  const signedBody = Buffer.concat([body, signature]);

  // 🔒 HMAC sur tout sauf HMAC lui-même
  const hmacKey = typeof HMAC_SECRET !== 'undefined' && HMAC_SECRET ? HMAC_SECRET : 'archipel-secret-temp';
  const hmac = crypto.createHmac("sha256", hmacKey).update(signedBody).digest();

  return Buffer.concat([signedBody, hmac]);
}

function parsePacket(buffer) {
  const magic = buffer.slice(0, 4).toString();
  const type = buffer.readUInt8(4);
  const nodeId = buffer.slice(5, 37);
  const payloadLen = buffer.readUInt32BE(37);

  const payloadStart = 41;
  const payloadEnd = payloadStart + payloadLen;

  const payload = buffer.slice(payloadStart, payloadEnd);

  const signatureStart = payloadEnd;
  const signatureEnd = signatureStart + 64;

  const signature = buffer.slice(signatureStart, signatureEnd);

  const hmac = buffer.slice(signatureEnd);

  return {
    magic,
    type,
    nodeId,
    payloadLen,
    payload,
    signature,
    hmac
  };
}

function verifyPacket(buffer) {
  const body = buffer.slice(0, buffer.length - 32);
  const receivedHmac = buffer.slice(buffer.length - 32);
  const hmacKey = typeof HMAC_SECRET !== 'undefined' && HMAC_SECRET ? HMAC_SECRET : 'archipel-secret-temp';
  const computedHmac = crypto.createHmac("sha256", hmacKey).update(body).digest();

  return crypto.timingSafeEqual(receivedHmac, computedHmac);
}

function extractPackets(buffer) {
  const packets = [];
  let offset = 0;

  while (offset + 41 <= buffer.length) {
    const payloadLen = buffer.readUInt32BE(offset + 37);
    const signatureLen = 64;
    const hmacLen = 32;
    const totalLength = 41 + payloadLen + signatureLen + hmacLen;

    if (offset + totalLength > buffer.length) {
      break; // packet incomplet
    }

    const packet = buffer.slice(offset, offset + totalLength);
    packets.push(packet);

    offset += totalLength;
  }

  return {
    packets,
    remaining: buffer.slice(offset)
  };
}

module.exports = {
  buildPacket,
  parsePacket,
  verifyPacket,
  extractPackets,
};