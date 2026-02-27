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

## Stack (détaillé)

- **Plateforme**: Node.js (v16+ recommandé)
- **Dépendances principales**:
	- `libsodium-wrappers` — primitives crypto modernes (Ed25519, etc.)
	- `dotenv` — gestion des variables d'environnement
	- `crypto` (module standard Node.js) — HMAC-SHA256

## `libsodium-wrappers`

Le projet utilise `libsodium-wrappers` pour:
- Génération et gestion des paires de clés Ed25519 (`crypto_sign_keypair`).
- Signatures détachées (`crypto_sign_detached`) pour authentifier les messages.

## Format exact du paquet (octets, offsets)

Layout binaire (offsets en octets, big-endian):

- 0..3   : `MAGIC` (4 octets) — ASCII `ARCH` (0x41 0x52 0x43 0x48)
- 4      : `type` (1 octet)
- 5..36  : `nodeId` (32 octets) — clé publique Ed25519
- 37..40 : `payloadLen` (4 octets) — UInt32BE
- 41..(40+N) : `payload` (N = payloadLen)
- (41+N)..(40+N+31) : `hmac` (32 octets) — HMAC-SHA256 over `header||payload`

Exemple: si `payloadLen = 10`, le `hmac` commence à l'offset 51.

## Schéma ASCII architecture

```
					+----------------------+        UDP Multicast
					|  Discovery (UDP)     |<-------------------------->
					|  - multicast receiver |                           
					+----------------------+                           
										^                                        
										|                                        
								 TCP|                                        
										|                                        
	+-----------------+-----------------+      +----------------+ 
	| Local Node (process Node.js)      |------| Peer Node      |
	| - src/index.js                     | TCP  | - remote node  |
	| - src/crypto/keys.js  (Ed25519)    |      +----------------+
	| - src/protocol/packet.js (HMAC)    |                       
	+------------------------------------+                       
```

## Justification: UDP + TCP

- UDP (multicast) : utilisé pour discovery/broadcast léger et faible latence. Permet à plusieurs noeuds d'annoncer leur présence sans état de connexion.
- TCP : utilisé pour échanges fiables, ordonnés et plus volumineux (ex: transferts d'état, messages critiques). Les paquets binaires sont encapsulés sur TCP quand la fiabilité est requise.

Cette combinaison permet discovery rapide (UDP) et transfert fiable (TCP).

## Primitives cryptographiques utilisées

- **Ed25519 (libsodium)** : signatures numériques pour prouver l'authenticité d'un noeud (`crypto_sign_keypair`, `crypto_sign_detached`). Avantages: rapide, petites clés, résistant aux attaques connues.
- **HMAC-SHA256 (Node `crypto`)** : intégrité et authentification des paquets (HMAC sur `header||payload`). La clé HMAC est fournie via `HMAC_SECRET` et doit être partagée hors dépôt.

Remarques:
- Les clés privées Ed25519 sont générées à l'initialisation en mémoire; ne les commitez jamais.
- Pour une phase ultérieure, on pourra envisager l'utilisation d'AEAD (ex: XChaCha20-Poly1305) pour confidentialité en plus de l'authenticité.