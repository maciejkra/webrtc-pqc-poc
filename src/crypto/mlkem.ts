/**
 * ML-KEM (Kyber) Post-Quantum Key Encapsulation Module
 *
 * This module provides PQC key exchange using ML-KEM-768 (Kyber768)
 * which is NIST's standardized post-quantum KEM algorithm.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface PQCSession {
  keyPair: KeyPair;
  sharedSecret?: Uint8Array;
  peerPublicKey?: Uint8Array;
  encapsulatedKey?: Uint8Array;
}

/**
 * Generate a new ML-KEM-768 key pair
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

/**
 * Encapsulate a shared secret using peer's public key
 * Returns ciphertext to send to peer and the shared secret
 */
export function encapsulate(peerPublicKey: Uint8Array): EncapsulationResult {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(peerPublicKey);
  return { ciphertext: cipherText, sharedSecret };
}

/**
 * Decapsulate to recover the shared secret using our secret key
 */
export function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, secretKey);
}

/**
 * Derive encryption key from shared secret using simple KDF
 * For production, use HKDF with proper context
 */
export async function deriveKey(sharedSecret: Uint8Array, context: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const contextBytes = encoder.encode(context);

  // Combine shared secret with context
  const combined = new Uint8Array(sharedSecret.length + contextBytes.length);
  combined.set(sharedSecret);
  combined.set(contextBytes, sharedSecret.length);

  // Hash to get key material
  const keyMaterial = await crypto.subtle.digest('SHA-256', combined);

  // Import as AES-GCM key
  return crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data using AES-GCM with PQC-derived key
 */
export async function encrypt(
  data: Uint8Array,
  key: CryptoKey
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // Create copies to ensure we have clean ArrayBuffer views
  const ivCopy = new Uint8Array(iv);
  const dataCopy = new Uint8Array(data);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivCopy },
    key,
    dataCopy
  );
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

/**
 * Decrypt data using AES-GCM with PQC-derived key
 */
export async function decrypt(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  // Create copies to ensure we have clean ArrayBuffer views
  const ivCopy = new Uint8Array(iv);
  const ciphertextCopy = new Uint8Array(ciphertext);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivCopy },
    key,
    ciphertextCopy
  );
  return new Uint8Array(plaintext);
}

/**
 * Encode bytes to base64 for transmission
 */
export function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Decode base64 to bytes
 */
export function fromBase64(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  return new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
}

/**
 * Get algorithm information for display
 */
export function getAlgorithmInfo() {
  return {
    name: 'ML-KEM-768 (Kyber768)',
    type: 'Key Encapsulation Mechanism',
    securityLevel: 'NIST Level 3 (equivalent to AES-192)',
    publicKeySize: 1184,
    secretKeySize: 2400,
    ciphertextSize: 1088,
    sharedSecretSize: 32,
    standard: 'FIPS 203 (2024)'
  };
}
