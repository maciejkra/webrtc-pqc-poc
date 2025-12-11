/**
 * WebRTC PQC Signaling Server
 *
 * This server handles:
 * 1. PQC key exchange between clients
 * 2. WebRTC signaling (SDP offer/answer, ICE candidates)
 * 3. Room management for peer connections
 */

import express from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateKeyPair,
  encapsulate,
  decapsulate,
  deriveKey,
  encrypt,
  decrypt,
  toBase64,
  fromBase64,
  getAlgorithmInfo,
  type KeyPair
} from '../crypto/mlkem.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// Store for rooms and clients
interface Client {
  id: string;
  ws: WebSocket;
  roomId?: string;
  pqcKeyPair: KeyPair;
  peerPublicKey?: Uint8Array;
  sharedSecret?: Uint8Array;
  encryptionKey?: CryptoKey;
  pqcEstablished: boolean;
}

interface Room {
  id: string;
  clients: Map<string, Client>;
  createdAt: Date;
}

const clients = new Map<string, Client>();
const rooms = new Map<string, Room>();

// Serve static files
app.use(express.static(path.join(__dirname, '../../public')));

// API endpoint for server info
app.get('/api/info', (req, res) => {
  res.json({
    server: 'WebRTC-PQC-PoC',
    version: '1.0.0',
    pqcAlgorithm: getAlgorithmInfo(),
    activeRooms: rooms.size,
    activeClients: clients.size
  });
});

// API endpoint to create a room
app.post('/api/room', (req, res) => {
  const roomId = uuidv4().substring(0, 8);
  rooms.set(roomId, {
    id: roomId,
    clients: new Map(),
    createdAt: new Date()
  });
  res.json({ roomId });
});

// WebSocket handling
wss.on('connection', async (ws: WebSocket) => {
  const clientId = uuidv4();
  const keyPair = generateKeyPair();

  const client: Client = {
    id: clientId,
    ws,
    pqcKeyPair: keyPair,
    pqcEstablished: false
  };

  clients.set(clientId, client);

  console.log(`[Server] Client connected: ${clientId}`);

  // Send welcome message with server's public key for this client
  sendMessage(ws, {
    type: 'welcome',
    clientId,
    serverPublicKey: toBase64(keyPair.publicKey),
    algorithm: getAlgorithmInfo()
  });

  ws.on('message', async (data: Buffer) => {
    try {
      const message = JSON.parse(data.toString());
      await handleMessage(client, message);
    } catch (error) {
      console.error(`[Server] Error handling message:`, error);
      sendMessage(ws, { type: 'error', message: 'Invalid message format' });
    }
  });

  ws.on('close', () => {
    console.log(`[Server] Client disconnected: ${clientId}`);
    handleDisconnect(client);
    clients.delete(clientId);
  });

  ws.on('error', (error) => {
    console.error(`[Server] WebSocket error for ${clientId}:`, error);
  });
});

async function handleMessage(client: Client, message: any) {
  console.log(`[Server] Received ${message.type} from ${client.id}`);

  switch (message.type) {
    case 'pqc-init':
      // Client sends their public key and encapsulated key
      await handlePQCInit(client, message);
      break;

    case 'join-room':
      await handleJoinRoom(client, message);
      break;

    case 'leave-room':
      handleLeaveRoom(client);
      break;

    case 'offer':
    case 'answer':
    case 'ice-candidate':
      // Forward WebRTC signaling messages (encrypted if PQC established)
      await handleSignaling(client, message);
      break;

    case 'encrypted-signaling':
      // Handle encrypted signaling message
      await handleEncryptedSignaling(client, message);
      break;

    default:
      sendMessage(client.ws, { type: 'error', message: `Unknown message type: ${message.type}` });
  }
}

async function handlePQCInit(client: Client, message: any) {
  try {
    const clientPublicKey = fromBase64(message.publicKey);
    const clientCiphertext = fromBase64(message.ciphertext);

    // Store client's public key
    client.peerPublicKey = clientPublicKey;

    // Decapsulate to get shared secret from client's encapsulation
    const sharedSecretFromClient = decapsulate(clientCiphertext, client.pqcKeyPair.secretKey);

    // Now encapsulate a key to send to the client
    const { ciphertext: serverCiphertext, sharedSecret: sharedSecretToClient } =
      encapsulate(clientPublicKey);

    // Combine both shared secrets (bidirectional key exchange)
    const combinedSecret = new Uint8Array(sharedSecretFromClient.length + sharedSecretToClient.length);
    combinedSecret.set(sharedSecretFromClient);
    combinedSecret.set(sharedSecretToClient, sharedSecretFromClient.length);

    // Hash combined secret for final shared key
    const finalSecretBuffer = await crypto.subtle.digest('SHA-256', combinedSecret);
    client.sharedSecret = new Uint8Array(finalSecretBuffer);

    // Derive encryption key
    client.encryptionKey = await deriveKey(client.sharedSecret, 'webrtc-pqc-signaling');
    client.pqcEstablished = true;

    console.log(`[Server] PQC established with client ${client.id}`);

    sendMessage(client.ws, {
      type: 'pqc-complete',
      ciphertext: toBase64(serverCiphertext),
      status: 'success',
      algorithm: getAlgorithmInfo()
    });
  } catch (error) {
    console.error(`[Server] PQC init error:`, error);
    sendMessage(client.ws, { type: 'pqc-error', message: 'PQC key exchange failed' });
  }
}

async function handleJoinRoom(client: Client, message: any) {
  const { roomId } = message;

  // Leave current room if any
  if (client.roomId) {
    handleLeaveRoom(client);
  }

  // Create room if it doesn't exist
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      id: roomId,
      clients: new Map(),
      createdAt: new Date()
    });
  }

  const room = rooms.get(roomId)!;
  room.clients.set(client.id, client);
  client.roomId = roomId;

  console.log(`[Server] Client ${client.id} joined room ${roomId}`);

  // Notify the new client about existing peers
  const existingPeers = Array.from(room.clients.keys()).filter(id => id !== client.id);

  sendMessage(client.ws, {
    type: 'room-joined',
    roomId,
    peers: existingPeers,
    pqcStatus: client.pqcEstablished ? 'established' : 'pending'
  });

  // Notify existing peers about new client
  for (const [peerId, peer] of room.clients) {
    if (peerId !== client.id) {
      sendMessage(peer.ws, {
        type: 'peer-joined',
        peerId: client.id,
        pqcStatus: client.pqcEstablished ? 'established' : 'pending'
      });
    }
  }
}

function handleLeaveRoom(client: Client) {
  if (!client.roomId) return;

  const room = rooms.get(client.roomId);
  if (room) {
    room.clients.delete(client.id);

    // Notify other clients
    for (const [_, peer] of room.clients) {
      sendMessage(peer.ws, {
        type: 'peer-left',
        peerId: client.id
      });
    }

    // Clean up empty rooms
    if (room.clients.size === 0) {
      rooms.delete(client.roomId);
    }
  }

  client.roomId = undefined;
}

async function handleSignaling(client: Client, message: any) {
  const { targetId, ...signalData } = message;

  if (!client.roomId) {
    sendMessage(client.ws, { type: 'error', message: 'Not in a room' });
    return;
  }

  const room = rooms.get(client.roomId);
  if (!room) return;

  // Find target client
  let targetClient: Client | undefined;

  if (targetId) {
    targetClient = room.clients.get(targetId);
  } else {
    // If no target specified, send to first other peer in room
    for (const [id, peer] of room.clients) {
      if (id !== client.id) {
        targetClient = peer;
        break;
      }
    }
  }

  if (!targetClient) {
    sendMessage(client.ws, { type: 'error', message: 'Target peer not found' });
    return;
  }

  // Forward the signaling message
  sendMessage(targetClient.ws, {
    ...signalData,
    fromId: client.id,
    pqcEncrypted: false // Plain signaling for now, encrypted version below
  });
}

async function handleEncryptedSignaling(client: Client, message: any) {
  if (!client.pqcEstablished || !client.encryptionKey) {
    sendMessage(client.ws, { type: 'error', message: 'PQC not established' });
    return;
  }

  try {
    // Decrypt the incoming message
    const ciphertext = fromBase64(message.ciphertext);
    const iv = fromBase64(message.iv);
    const plaintext = await decrypt(ciphertext, iv, client.encryptionKey);
    const decryptedMessage = JSON.parse(new TextDecoder().decode(plaintext));

    console.log(`[Server] Decrypted signaling: ${decryptedMessage.type}`);

    // Process the decrypted signaling message
    await handleSignaling(client, {
      ...decryptedMessage,
      pqcEncrypted: true
    });
  } catch (error) {
    console.error(`[Server] Encrypted signaling error:`, error);
    sendMessage(client.ws, { type: 'error', message: 'Failed to decrypt signaling message' });
  }
}

function handleDisconnect(client: Client) {
  handleLeaveRoom(client);
}

function sendMessage(ws: WebSocket, message: any) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║     WebRTC PQC Proof of Concept Server                     ║
║                                                            ║
║     Algorithm: ML-KEM-768 (Kyber768) - FIPS 203            ║
║     Security:  NIST Level 3 (AES-192 equivalent)           ║
║                                                            ║
║     Server running on port ${PORT}                            ║
║     Open http://localhost:${PORT} in your browser              ║
╚════════════════════════════════════════════════════════════╝
  `);
});
