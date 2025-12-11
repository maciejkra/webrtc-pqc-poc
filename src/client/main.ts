/**
 * WebRTC PQC Client - Main Entry Point
 */

import { createPQCClient, type PQCState } from './pqc-client.js';

// DOM Elements
const statusIndicator = document.getElementById('status-indicator') as HTMLDivElement;
const statusText = document.getElementById('status-text') as HTMLSpanElement;
const algorithmName = document.getElementById('algorithm-name') as HTMLSpanElement;
const securityLevel = document.getElementById('security-level') as HTMLSpanElement;
const keyExchangeTime = document.getElementById('key-exchange-time') as HTMLSpanElement;
const publicKeySize = document.getElementById('public-key-size') as HTMLSpanElement;
const ciphertextSize = document.getElementById('ciphertext-size') as HTMLSpanElement;
const sharedSecretStatus = document.getElementById('shared-secret-status') as HTMLSpanElement;

// DTLS/Media stats elements
const dtlsCipherEl = document.getElementById('dtls-cipher') as HTMLSpanElement;
const dtlsGroupEl = document.getElementById('dtls-group') as HTMLSpanElement;
const srtpCipherEl = document.getElementById('srtp-cipher') as HTMLSpanElement;
const mediaPqcStatusEl = document.getElementById('media-pqc-status') as HTMLSpanElement;
const pqcMediaMethodEl = document.getElementById('pqc-media-method') as HTMLSpanElement;

const roomInput = document.getElementById('room-input') as HTMLInputElement;
const joinBtn = document.getElementById('join-btn') as HTMLButtonElement;
const hangupBtn = document.getElementById('hangup-btn') as HTMLButtonElement;
const generateRoomBtn = document.getElementById('generate-room-btn') as HTMLButtonElement;

const localVideo = document.getElementById('local-video') as HTMLVideoElement;
const remoteVideo = document.getElementById('remote-video') as HTMLVideoElement;

const logsContainer = document.getElementById('logs') as HTMLDivElement;

// Initialize client
const pqcClient = createPQCClient();

// State update handler
pqcClient.onStateChange = (state: PQCState) => {
  updateStatusUI(state);
};

// Stream handlers
pqcClient.onLocalStream = (stream: MediaStream) => {
  localVideo.srcObject = stream;
  log('Local media stream acquired', 'success');
};

pqcClient.onRemoteStream = (stream: MediaStream) => {
  remoteVideo.srcObject = stream;
  log('Remote media stream received - PQC WebRTC connection established!', 'success');
};

// Message handler for logging
pqcClient.onMessage = (message: any) => {
  const msgType = message.type;
  let logType: 'info' | 'success' | 'warning' | 'error' = 'info';

  if (msgType.includes('error')) logType = 'error';
  else if (msgType.includes('complete') || msgType.includes('joined')) logType = 'success';
  else if (msgType.includes('left')) logType = 'warning';

  log(`[${msgType}] ${JSON.stringify(message).substring(0, 100)}...`, logType);
};

function updateStatusUI(state: PQCState) {
  // Update status indicator
  statusIndicator.className = `status-indicator ${state.status}`;
  statusText.textContent = formatStatus(state.status);

  // Update algorithm info
  if (state.algorithm) {
    algorithmName.textContent = state.algorithm.name || 'ML-KEM-768';
    securityLevel.textContent = state.algorithm.securityLevel || 'NIST Level 3';
    publicKeySize.textContent = `${state.algorithm.publicKeySize || 1184} bytes`;
    ciphertextSize.textContent = `${state.algorithm.ciphertextSize || 1088} bytes`;
  }

  // Update key exchange time
  if (state.keyExchangeTime) {
    keyExchangeTime.textContent = `${state.keyExchangeTime.toFixed(2)} ms`;
  }

  // Update shared secret status
  sharedSecretStatus.textContent = state.sharedSecretDerived ? 'Derived' : 'Pending';
  sharedSecretStatus.className = state.sharedSecretDerived ? 'success' : 'pending';

  // Update DTLS/Media stats
  if (dtlsCipherEl && state.dtlsCipher) {
    dtlsCipherEl.textContent = state.dtlsCipher;
  }
  if (dtlsGroupEl && state.dtlsGroup) {
    dtlsGroupEl.textContent = state.dtlsGroup;
    // Highlight if PQC group
    if (state.dtlsGroup.includes('MLKEM') || state.dtlsGroup.includes('Kyber')) {
      dtlsGroupEl.className = 'algo-value pqc-active';
    }
  }
  if (srtpCipherEl && state.srtpCipher) {
    srtpCipherEl.textContent = state.srtpCipher || 'N/A';
  }
  if (mediaPqcStatusEl) {
    // Check for PQC media via Insertable Streams first (our implementation)
    if (state.pqcMediaEnabled) {
      mediaPqcStatusEl.textContent = `PQC Active (${state.pqcMediaMethod})`;
      mediaPqcStatusEl.className = 'status-value success';
    } else if (state.dtlsPqcEnabled) {
      // Native DTLS PQC (browser support)
      mediaPqcStatusEl.textContent = 'PQC Active (X25519MLKEM768)';
      mediaPqcStatusEl.className = 'status-value success';
    } else if (state.pqcMediaMethod === 'pending') {
      mediaPqcStatusEl.textContent = 'PQC Pending...';
      mediaPqcStatusEl.className = 'status-value pending';
    } else if (state.pqcMediaMethod === 'not-supported') {
      mediaPqcStatusEl.textContent = 'Not Supported (need Chrome 86+)';
      mediaPqcStatusEl.className = 'status-value warning';
    } else if (state.dtlsCipher) {
      mediaPqcStatusEl.textContent = 'Classical (ECDHE) + PQC Layer';
      mediaPqcStatusEl.className = 'status-value warning';
    } else {
      mediaPqcStatusEl.textContent = 'Not Connected';
      mediaPqcStatusEl.className = 'status-value pending';
    }
  }

  // Update PQC media method display
  if (pqcMediaMethodEl) {
    if (state.pqcMediaEnabled && state.pqcMediaMethod) {
      pqcMediaMethodEl.textContent = state.pqcMediaMethod;
      pqcMediaMethodEl.className = 'algo-value pqc-active';
    } else if (state.pqcMediaMethod === 'not-supported') {
      pqcMediaMethodEl.textContent = 'Insertable Streams not available';
      pqcMediaMethodEl.className = 'algo-value';
    } else {
      pqcMediaMethodEl.textContent = state.pqcMediaMethod || '--';
    }
  }

  // Update button states
  joinBtn.disabled = state.status !== 'established';
  hangupBtn.disabled = state.status !== 'established';
}

function formatStatus(status: string): string {
  const statusMap: Record<string, string> = {
    'disconnected': 'Disconnected',
    'connecting': 'Connecting...',
    'pqc-handshake': 'PQC Handshake in Progress...',
    'established': 'PQC Secure Connection Established',
    'error': 'Error'
  };
  return statusMap[status] || status;
}

function log(message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  const logEntry = document.createElement('div');
  logEntry.className = `log-entry ${type}`;
  logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${message}`;
  logsContainer.appendChild(logEntry);
  logsContainer.scrollTop = logsContainer.scrollHeight;
}

// Event handlers
generateRoomBtn.addEventListener('click', () => {
  const roomId = Math.random().toString(36).substring(2, 10);
  roomInput.value = roomId;
  log(`Generated room ID: ${roomId}`, 'info');
});

joinBtn.addEventListener('click', async () => {
  const roomId = roomInput.value.trim();
  if (!roomId) {
    log('Please enter a room ID', 'warning');
    return;
  }

  try {
    log(`Joining room: ${roomId}`, 'info');
    await pqcClient.joinRoom(roomId);
  } catch (error) {
    log(`Failed to join room: ${error}`, 'error');
  }
});

hangupBtn.addEventListener('click', () => {
  pqcClient.hangup();
  localVideo.srcObject = null;
  remoteVideo.srcObject = null;
  log('Call ended', 'warning');
});

// Connect on page load
async function init() {
  log('Initializing WebRTC PQC Client...', 'info');
  log('Post-Quantum Cryptography: ML-KEM-768 (Kyber768) - FIPS 203', 'info');

  try {
    // Determine WebSocket URL based on current location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;

    log(`Connecting to signaling server: ${wsUrl}`, 'info');
    await pqcClient.connect(wsUrl);
    log('Connected and PQC key exchange complete!', 'success');
  } catch (error) {
    log(`Connection failed: ${error}`, 'error');
  }
}

// Start
init();
