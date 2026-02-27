
const { initKeys } = require("./crypto/keys");
const { startTCPServer } = require("./network/tcpServer");


async function main() {
  await initKeys();
  startTCPServer(7777);
}

main();