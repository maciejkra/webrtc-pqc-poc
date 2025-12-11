/**
 * PQC WebRTC Client
 *
 * Handles ML-KEM key exchange and WebRTC connection establishment
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { setupPQCTransforms, isInsertableStreamsSupported } from './pqc-transform.js';

export interface PQCState {
  status: 'disconnected' | 'connecting' | 'pqc-handshake' | 'established' | 'error';
  algorithm?: {
    name: string;
    securityLevel: string;
    publicKeySize: number;
    ciphertextSize: number;
  };
  keyExchangeTime?: number;
  sharedSecretDerived: boolean;
  // DTLS/Media encryption stats
  dtlsCipher?: string;
  dtlsGroup?: string;
  srtpCipher?: string;
  dtlsPqcEnabled?: boolean;
  // PQC Media layer (Insertable Streams)
  pqcMediaEnabled?: boolean;
  pqcMediaMethod?: string;
}

export interface PQCClient {
  state: PQCState;
  connect(wsUrl: string): Promise<void>;
  joinRoom(roomId: string): Promise<void>;
  startCall(): Promise<void>;
  hangup(): void;
  getStats(): Promise<RTCStatsReport | null>;
  onStateChange: (state: PQCState) => void;
  onLocalStream: (stream: MediaStream) => void;
  onRemoteStream: (stream: MediaStream) => void;
  onMessage: (message: any) => void;
}

// Check if browser supports PQC DTLS (experimental)
function detectPQCDTLSSupport(): { supported: boolean; method: string } {
  // Check for Chrome's experimental flag
  const hasWebRTCPQC = typeof (RTCPeerConnection.prototype as any).setConfiguration === 'function';

  // Check user agent for known PQC-supporting browsers
  const ua = navigator.userAgent;
  const isFirefoxNightly = ua.includes('Firefox') && (ua.includes('Nightly') || parseInt(ua.match(/Firefox\/(\d+)/)?.[1] || '0') >= 134);
  const isChromeCanary = ua.includes('Chrome') && parseInt(ua.match(/Chrome\/(\d+)/)?.[1] || '0') >= 131;

  if (isFirefoxNightly) {
    return { supported: true, method: 'firefox-nightly' };
  }
  if (isChromeCanary) {
    return { supported: true, method: 'chrome-experimental' };
  }

  return { supported: false, method: 'none' };
}

export function createPQCClient(): PQCClient {
  let ws: WebSocket | null = null;
  let clientId: string = '';
  let roomId: string = '';
  let peerConnection: RTCPeerConnection | null = null;
  let localStream: MediaStream | null = null;

  // PQC state
  let keyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  let serverPublicKey: Uint8Array | null = null;
  let sharedSecret: Uint8Array | null = null;
  let encryptionKey: CryptoKey | null = null;
  let keyExchangeStartTime: number = 0;
  let pqcMediaSecret: Uint8Array | null = null; // For media encryption

  const state: PQCState = {
    status: 'disconnected',
    sharedSecretDerived: false
  };

  const client: PQCClient = {
    state,
    onStateChange: () => {},
    onLocalStream: () => {},
    onRemoteStream: () => {},
    onMessage: () => {},

    async connect(wsUrl: string) {
      return new Promise((resolve, reject) => {
        updateState({ status: 'connecting' });

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('[PQC Client] WebSocket connected');
        };

        ws.onmessage = async (event) => {
          const message = JSON.parse(event.data);
          await handleMessage(message);

          if (message.type === 'pqc-complete' && state.status === 'established') {
            resolve();
          }
        };

        ws.onerror = (error) => {
          console.error('[PQC Client] WebSocket error:', error);
          updateState({ status: 'error' });
          reject(error);
        };

        ws.onclose = () => {
          console.log('[PQC Client] WebSocket closed');
          updateState({ status: 'disconnected' });
        };
      });
    },

    async joinRoom(newRoomId: string) {
      roomId = newRoomId;
      sendMessage({ type: 'join-room', roomId });
    },

    async startCall() {
      try {
        // Get local media
        localStream = await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: true
        });
        client.onLocalStream(localStream);

        // Create peer connection
        await createPeerConnection();
      } catch (error) {
        console.error('[PQC Client] Start call error:', error);
        throw error;
      }
    },

    hangup() {
      if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
      }
      if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
      }
      if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
      }
      sendMessage({ type: 'leave-room' });
    },

    async getStats(): Promise<RTCStatsReport | null> {
      if (!peerConnection) return null;
      return peerConnection.getStats();
    }
  };

  let statsInterval: ReturnType<typeof setInterval> | null = null;

  function startStatsMonitoring() {
    if (statsInterval) clearInterval(statsInterval);

    statsInterval = setInterval(async () => {
      if (!peerConnection) return;

      try {
        const stats = await peerConnection.getStats();
        stats.forEach((report) => {
          if (report.type === 'transport') {
            const dtlsCipher = report.dtlsCipher || 'N/A';
            const srtpCipher = report.srtpCipher || 'N/A';
            // dtlsGroup is proposed but may not exist yet
            const dtlsGroup = (report as any).dtlsGroup || (report as any).tlsGroup || 'N/A';

            // Check if PQC is in use (look for MLKEM or Kyber in the cipher/group)
            const isPQC = dtlsCipher.includes('MLKEM') ||
                          dtlsCipher.includes('Kyber') ||
                          dtlsGroup.includes('MLKEM') ||
                          dtlsGroup.includes('Kyber') ||
                          dtlsGroup.includes('25519MLKEM');

            updateState({
              dtlsCipher,
              srtpCipher,
              dtlsGroup,
              dtlsPqcEnabled: isPQC
            });

            if (isPQC) {
              console.log('[PQC Client] PQC DTLS ACTIVE:', dtlsGroup, dtlsCipher);
            }
          }
        });
      } catch (e) {
        // Stats may not be available yet
      }
    }, 1000);
  }

  function updateState(updates: Partial<PQCState>) {
    Object.assign(state, updates);
    client.onStateChange({ ...state });
  }

  async function handleMessage(message: any) {
    console.log('[PQC Client] Received:', message.type);
    client.onMessage(message);

    switch (message.type) {
      case 'welcome':
        clientId = message.clientId;
        serverPublicKey = fromBase64(message.serverPublicKey);
        updateState({
          status: 'pqc-handshake',
          algorithm: message.algorithm
        });
        await initiatePQCHandshake();
        break;

      case 'pqc-complete':
        await completePQCHandshake(message);
        break;

      case 'pqc-error':
        console.error('[PQC Client] PQC error:', message.message);
        updateState({ status: 'error' });
        break;

      case 'room-joined':
        console.log('[PQC Client] Joined room:', message.roomId, 'peers:', message.peers);
        // If there are existing peers, we should initiate the call
        if (message.peers.length > 0) {
          await client.startCall();
          await createOffer();
        }
        break;

      case 'peer-joined':
        console.log('[PQC Client] Peer joined:', message.peerId);
        // New peer will initiate the call
        break;

      case 'peer-left':
        console.log('[PQC Client] Peer left:', message.peerId);
        if (peerConnection) {
          peerConnection.close();
          peerConnection = null;
        }
        break;

      case 'offer':
        await handleOffer(message);
        break;

      case 'answer':
        await handleAnswer(message);
        break;

      case 'ice-candidate':
        await handleIceCandidate(message);
        break;
    }
  }

  async function initiatePQCHandshake() {
    if (!serverPublicKey) return;

    keyExchangeStartTime = performance.now();

    // Generate our key pair
    const keys = ml_kem768.keygen();
    keyPair = { publicKey: keys.publicKey, secretKey: keys.secretKey };

    // Encapsulate a shared secret using server's public key
    const { cipherText, sharedSecret: encapSecret } = ml_kem768.encapsulate(serverPublicKey);

    // Store partial shared secret (will be combined with server's encapsulation)
    sharedSecret = encapSecret;

    // Send our public key and the encapsulated secret
    sendMessage({
      type: 'pqc-init',
      publicKey: toBase64(keyPair.publicKey),
      ciphertext: toBase64(cipherText)
    });
  }

  async function completePQCHandshake(message: any) {
    if (!keyPair || !sharedSecret) return;

    // Decapsulate server's ciphertext to get their shared secret
    const serverCiphertext = fromBase64(message.ciphertext);
    const serverSharedSecret = ml_kem768.decapsulate(serverCiphertext, keyPair.secretKey);

    // Combine both shared secrets (same order as server)
    const combinedSecret = new Uint8Array(sharedSecret.length + serverSharedSecret.length);
    combinedSecret.set(sharedSecret);
    combinedSecret.set(serverSharedSecret, sharedSecret.length);

    // Hash combined secret
    const finalSecretBuffer = await crypto.subtle.digest('SHA-256', combinedSecret);
    const finalSecret = new Uint8Array(finalSecretBuffer);

    // Store the shared secret for media encryption
    pqcMediaSecret = finalSecret;

    // Derive encryption key for signaling
    encryptionKey = await deriveKey(finalSecret, 'webrtc-pqc-signaling');

    const keyExchangeTime = performance.now() - keyExchangeStartTime;

    console.log(`[PQC Client] PQC established in ${keyExchangeTime.toFixed(2)}ms`);

    // Check if Insertable Streams is supported for media PQC
    const insertableStreamsSupported = isInsertableStreamsSupported();
    console.log(`[PQC Client] Insertable Streams supported: ${insertableStreamsSupported}`);

    updateState({
      status: 'established',
      sharedSecretDerived: true,
      keyExchangeTime,
      algorithm: message.algorithm,
      pqcMediaEnabled: false, // Will be set true when transforms are applied
      pqcMediaMethod: insertableStreamsSupported ? 'pending' : 'not-supported'
    });
  }

  async function deriveKey(secret: Uint8Array, context: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const contextBytes = encoder.encode(context);
    const combined = new Uint8Array(secret.length + contextBytes.length);
    combined.set(secret);
    combined.set(contextBytes, secret.length);

    const keyMaterial = await crypto.subtle.digest('SHA-256', combined);

    return crypto.subtle.importKey(
      'raw',
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function createPeerConnection() {
    const pqcSupport = detectPQCDTLSSupport();
    console.log('[PQC Client] PQC DTLS support:', pqcSupport);

    // Base configuration
    const config: RTCConfiguration & { cryptoOptions?: any } = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
      ]
    };

    // Try to enable PQC DTLS if browser supports it
    // This uses the proposed W3C API: https://github.com/w3c/webrtc-extensions/issues/207
    if (pqcSupport.supported) {
      try {
        // Proposed API for PQC DTLS
        (config as any).cryptoOptions = {
          dtls: {
            // X25519MLKEM768 is the hybrid classical+PQC key exchange
            groups: ['X25519MLKEM768', 'X25519']
          }
        };
        console.log('[PQC Client] Attempting PQC DTLS with X25519MLKEM768');
        updateState({ dtlsPqcEnabled: true });
      } catch (e) {
        console.warn('[PQC Client] Failed to set PQC DTLS options:', e);
        updateState({ dtlsPqcEnabled: false });
      }
    } else {
      console.log('[PQC Client] Browser does not support PQC DTLS yet');
      console.log('[PQC Client] To enable PQC DTLS:');
      console.log('  - Chrome: chrome://flags/#enable-webrtc-dtls-pqc');
      console.log('  - Firefox Nightly: about:config -> security.tls.enable_kyber');
      updateState({ dtlsPqcEnabled: false });
    }

    peerConnection = new RTCPeerConnection(config);

    // Start monitoring DTLS stats
    startStatsMonitoring();

    // Add local tracks
    if (localStream) {
      localStream.getTracks().forEach(track => {
        peerConnection!.addTrack(track, localStream!);
      });
    }

    // Handle ICE candidates
    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        sendMessage({
          type: 'ice-candidate',
          candidate: event.candidate.toJSON()
        });
      }
    };

    // Handle remote stream
    peerConnection.ontrack = (event) => {
      console.log('[PQC Client] Remote track received');
      if (event.streams[0]) {
        client.onRemoteStream(event.streams[0]);
      }
    };

    peerConnection.oniceconnectionstatechange = () => {
      console.log('[PQC Client] ICE state:', peerConnection?.iceConnectionState);
    };

    peerConnection.onconnectionstatechange = async () => {
      console.log('[PQC Client] Connection state:', peerConnection?.connectionState);

      // Set up PQC media transforms when connected
      if (peerConnection?.connectionState === 'connected' && pqcMediaSecret) {
        try {
          console.log('[PQC Client] Setting up PQC media encryption...');
          const result = await setupPQCTransforms(peerConnection, pqcMediaSecret);

          if (result.supported) {
            console.log(`[PQC Client] PQC media encryption ACTIVE via ${result.method}`);
            updateState({
              pqcMediaEnabled: true,
              pqcMediaMethod: result.method
            });
          } else {
            console.warn('[PQC Client] PQC media encryption not available');
            updateState({
              pqcMediaEnabled: false,
              pqcMediaMethod: 'not-supported'
            });
          }
        } catch (e) {
          console.error('[PQC Client] Failed to set up PQC media transforms:', e);
          updateState({
            pqcMediaEnabled: false,
            pqcMediaMethod: 'error'
          });
        }
      }
    };
  }

  async function createOffer() {
    if (!peerConnection) return;

    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);

    sendMessage({
      type: 'offer',
      sdp: offer.sdp
    });
  }

  async function handleOffer(message: any) {
    if (!localStream) {
      await client.startCall();
    }

    if (!peerConnection) {
      await createPeerConnection();
    }

    await peerConnection!.setRemoteDescription({
      type: 'offer',
      sdp: message.sdp
    });

    const answer = await peerConnection!.createAnswer();
    await peerConnection!.setLocalDescription(answer);

    sendMessage({
      type: 'answer',
      sdp: answer.sdp
    });
  }

  async function handleAnswer(message: any) {
    if (!peerConnection) return;

    await peerConnection.setRemoteDescription({
      type: 'answer',
      sdp: message.sdp
    });
  }

  async function handleIceCandidate(message: any) {
    if (!peerConnection) return;

    try {
      await peerConnection.addIceCandidate(message.candidate);
    } catch (error) {
      console.error('[PQC Client] Error adding ICE candidate:', error);
    }
  }

  function sendMessage(message: any) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  function toBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
  }

  function fromBase64(base64: string): Uint8Array {
    return new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
  }

  return client;
}
