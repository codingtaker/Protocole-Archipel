const net = require("net");
const { extractPackets, verifyPacket } = require("../protocol/packet");

function startTCPServer(port) {
  const server = net.createServer((socket) => {
    console.log("📡 Nouveau client connecté");

    let buffer = Buffer.alloc(0);

    socket.on("data", (data) => {
      buffer = Buffer.concat([buffer, data]);

      const result = extractPackets(buffer);

      result.packets.forEach(packet => {
        if (!verifyPacket(packet)) {
          console.log("❌ Packet invalide rejeté");
          return;
        }

        console.log("✔ Packet valide reçu :", packet.length, "bytes");
      });

      buffer = result.remaining;
    });

    socket.on("close", () => {
      console.log("🔌 Client déconnecté");
    });

    socket.on("error", (err) => {
      console.log("⚠️ Erreur socket:", err.message);
    });
  });

  server.listen(port, () => {
    console.log(`🚀 Serveur TCP démarré sur port ${port}`);
  });
}

module.exports = { startTCPServer };