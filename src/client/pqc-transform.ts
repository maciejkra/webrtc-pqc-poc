/**
 * PQC Media Transform using WebRTC Insertable Streams
 *
 * This adds a Post-Quantum encryption layer on top of SRTP using
 * the Encoded Transform API (RTCRtpScriptTransform).
 *
 * Architecture:
 *   Raw Media → Encoder → [PQC Encrypt] → SRTP → Network → SRTP → [PQC Decrypt] → Decoder → Playback
 *                         ^^^^^^^^^^^^                            ^^^^^^^^^^^^
 *                         Our PQC layer                           Our PQC layer
 */

// Check if Insertable Streams is supported
export function isInsertableStreamsSupported(): boolean {
  return typeof RTCRtpScriptTransform !== 'undefined' ||
         typeof (RTCRtpSender.prototype as any).createEncodedStreams === 'function';
}

/**
 * PQC Transform Worker code (runs in a separate worker thread)
 * Uses AES-GCM with PQC-derived key for frame encryption
 */
export function getPQCTransformWorkerCode(): string {
  return `
    let encryptionKey = null;
    let decryptionKey = null;
    let frameCounter = 0;

    // Import key from raw bytes
    async function importKey(keyBytes) {
      return await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    }

    // Encrypt a frame
    async function encryptFrame(frame, controller) {
      if (!encryptionKey) {
        controller.enqueue(frame);
        return;
      }

      try {
        const data = new Uint8Array(frame.data);

        // Create IV from frame counter (12 bytes)
        const iv = new Uint8Array(12);
        const view = new DataView(iv.buffer);
        view.setBigUint64(4, BigInt(frameCounter++), false);

        // Encrypt frame data
        const encrypted = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          encryptionKey,
          data
        );

        // Create new frame with: [IV (12 bytes)][Encrypted Data][Auth Tag (16 bytes)]
        const newData = new Uint8Array(12 + encrypted.byteLength);
        newData.set(iv, 0);
        newData.set(new Uint8Array(encrypted), 12);

        frame.data = newData.buffer;
        controller.enqueue(frame);
      } catch (e) {
        console.error('PQC encrypt error:', e);
        controller.enqueue(frame);
      }
    }

    // Decrypt a frame
    async function decryptFrame(frame, controller) {
      if (!decryptionKey) {
        controller.enqueue(frame);
        return;
      }

      try {
        const data = new Uint8Array(frame.data);

        // Check minimum size (IV + at least some data + auth tag)
        if (data.length < 28) {
          controller.enqueue(frame);
          return;
        }

        // Extract IV and encrypted data
        const iv = data.slice(0, 12);
        const encrypted = data.slice(12);

        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          decryptionKey,
          encrypted
        );

        frame.data = decrypted;
        controller.enqueue(frame);
      } catch (e) {
        // Decryption failed - might be unencrypted frame or wrong key
        console.warn('PQC decrypt error (may be unencrypted frame):', e.message);
        controller.enqueue(frame);
      }
    }

    // Handle messages from main thread
    onmessage = async (event) => {
      const { operation, key } = event.data;

      if (operation === 'setKey') {
        const keyBytes = new Uint8Array(key);
        encryptionKey = await importKey(keyBytes);
        decryptionKey = await importKey(keyBytes);
        console.log('[PQC Worker] Key set successfully');
        postMessage({ status: 'keySet' });
      }
    };

    // Handle transform streams
    onrtctransform = (event) => {
      const transformer = event.transformer;
      const readable = transformer.readable;
      const writable = transformer.writable;
      const options = transformer.options;

      const transform = options.name === 'encrypt' ? encryptFrame : decryptFrame;

      readable.pipeThrough(new TransformStream({ transform })).pipeTo(writable);

      console.log('[PQC Worker] Transform set up:', options.name);
    };
  `;
}

/**
 * Legacy approach using createEncodedStreams (older API)
 */
export function createLegacyPQCTransform(
  sender: RTCRtpSender | RTCRtpReceiver,
  key: Uint8Array,
  direction: 'encrypt' | 'decrypt'
): void {
  const senderAny = sender as any;

  if (typeof senderAny.createEncodedStreams !== 'function') {
    console.warn('[PQC Transform] createEncodedStreams not supported');
    return;
  }

  const { readable, writable } = senderAny.createEncodedStreams();
  let frameCounter = 0;

  const transformStream = new TransformStream({
    async transform(frame: any, controller: any) {
      try {
        // Create a fresh copy to avoid SharedArrayBuffer issues
        const keyCopy = new Uint8Array(key);
        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          keyCopy,
          { name: 'AES-GCM', length: 256 },
          false,
          [direction === 'encrypt' ? 'encrypt' : 'decrypt']
        );

        const data = new Uint8Array(frame.data);

        if (direction === 'encrypt') {
          const iv = new Uint8Array(12);
          const view = new DataView(iv.buffer);
          view.setBigUint64(4, BigInt(frameCounter++), false);

          const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            data
          );

          const newData = new Uint8Array(12 + encrypted.byteLength);
          newData.set(iv, 0);
          newData.set(new Uint8Array(encrypted), 12);
          frame.data = newData.buffer;
        } else {
          if (data.length >= 28) {
            const iv = data.slice(0, 12);
            const encrypted = data.slice(12);
            const decrypted = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv },
              cryptoKey,
              encrypted
            );
            frame.data = decrypted;
          }
        }
      } catch (e) {
        // Pass through on error
      }
      controller.enqueue(frame);
    }
  });

  readable.pipeThrough(transformStream).pipeTo(writable);
}

/**
 * Setup PQC transforms on a peer connection
 */
export async function setupPQCTransforms(
  pc: RTCPeerConnection,
  sharedSecret: Uint8Array
): Promise<{ supported: boolean; method: string }> {
  // Derive a key specifically for media encryption
  const keyMaterial = await crypto.subtle.digest(
    'SHA-256',
    new Uint8Array([...sharedSecret, ...new TextEncoder().encode('pqc-media-encryption')])
  );
  const mediaKey = new Uint8Array(keyMaterial);

  // Check for RTCRtpScriptTransform (modern API)
  if (typeof RTCRtpScriptTransform !== 'undefined') {
    console.log('[PQC Transform] Using RTCRtpScriptTransform (modern API)');

    // Create worker from inline code
    const workerCode = getPQCTransformWorkerCode();
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    const workerUrl = URL.createObjectURL(blob);

    // We need to set up transforms when tracks are added
    pc.getSenders().forEach(sender => {
      if (sender.track) {
        try {
          const worker = new Worker(workerUrl, { name: 'pqc-encrypt' });
          worker.postMessage({ operation: 'setKey', key: Array.from(mediaKey) });
          (sender as any).transform = new RTCRtpScriptTransform(worker, { name: 'encrypt' });
          console.log('[PQC Transform] Encrypt transform set for', sender.track.kind);
        } catch (e) {
          console.warn('[PQC Transform] Failed to set encrypt transform:', e);
        }
      }
    });

    pc.getReceivers().forEach(receiver => {
      if (receiver.track) {
        try {
          const worker = new Worker(workerUrl, { name: 'pqc-decrypt' });
          worker.postMessage({ operation: 'setKey', key: Array.from(mediaKey) });
          (receiver as any).transform = new RTCRtpScriptTransform(worker, { name: 'decrypt' });
          console.log('[PQC Transform] Decrypt transform set for', receiver.track.kind);
        } catch (e) {
          console.warn('[PQC Transform] Failed to set decrypt transform:', e);
        }
      }
    });

    return { supported: true, method: 'RTCRtpScriptTransform' };
  }

  // Check for createEncodedStreams (legacy API)
  const sender = pc.getSenders()[0];
  if (sender && typeof (sender as any).createEncodedStreams === 'function') {
    console.log('[PQC Transform] Using createEncodedStreams (legacy API)');

    pc.getSenders().forEach(s => {
      if (s.track) {
        createLegacyPQCTransform(s, mediaKey, 'encrypt');
      }
    });

    pc.getReceivers().forEach(r => {
      if (r.track) {
        createLegacyPQCTransform(r, mediaKey, 'decrypt');
      }
    });

    return { supported: true, method: 'createEncodedStreams' };
  }

  console.warn('[PQC Transform] No Insertable Streams API available');
  return { supported: false, method: 'none' };
}
