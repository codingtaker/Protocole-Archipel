# Archipel

## Stack choisie

- **Langage**: Node.js
- **Bibliothèques principales**: `libsodium-wrappers` pour les opérations cryptographiques, `dotenv` pour la configuration.
- **Autres**: `crypto` (lib standard Node) pour HMAC, TCP sockets pour la communication réseau.

## Format de paquet

Chaque paquet suit le format binaire suivant (Sprint 0):
- `MAGIC` (4 octets) — identifiant de protocole ("ARCH").
- `type` (1 octet) — type de message.
- `nodeId` (32 octets) — identifiant public du noeud (clé publique Ed25519).
- `payloadLen` (4 octets, big-endian) — longueur du payload.
- `payload` (variable) — données du message.
- `hmac` (32 octets) — HMAC-SHA256 calculé sur `header || payload`.

> Remarque : la clé utilisée pour le HMAC doit provenir d'une variable d'environnement (voir `.env.example`). Ne jamais committer de secrets en clair.

## Schéma architecture

- Noeud local (processus Node.js)
	- Génération des clés Ed25519 à l'initialisation (`src/crypto/keys.js`).
	- Construction et parsing des paquets (`src/protocol/packet.js`).
	- Configuration via `src/config.js` et variables d'environnement.
- Réseau
	- Communication TCP entre noeuds, discovery éventuelle via multicast.

## Sécurité
- Les clés privées ne doivent jamais être commitées. Les secrets (HMAC) doivent être fournis via la variable d'environnement `HMAC_SECRET`.
- Avant de marquer une release ou un sprint, vérifier l'absence de secrets committés et, si nécessaire, purger l'historique Git.

## Quickstart

1. Copier `.env.example` en `.env` et remplir `HMAC_SECRET`.
2. `npm install`
3. Lancer le noeud: `node src/index.js`