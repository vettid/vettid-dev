# E2EE Key Exchange Architecture via Vettid

## Overview

This document describes how to implement user-controlled end-to-end encryption for WebRTC voice/video calls using Vettid as the signaling server and Cloudflare TURN for relay.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           KEY EXCHANGE PHASE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐                    ┌──────────┐                              │
│   │  User A  │                    │  User B  │                              │
│   │  (Alice) │                    │   (Bob)  │                              │
│   └────┬─────┘                    └────┬─────┘                              │
│        │                               │                                    │
│        │  1. Generate ECDH keypair     │  1. Generate ECDH keypair          │
│        │     (ephemeral or persistent) │     (ephemeral or persistent)      │
│        │                               │                                    │
│        │  2. Send public key ──────────┼──────────────────────►             │
│        │     via Vettid signaling      │                                    │
│        │                               │                                    │
│        │  ◄────────────────────────────┼── 3. Send public key               │
│        │                               │      via Vettid signaling          │
│        │                               │                                    │
│        │  4. Derive shared secret      │  4. Derive shared secret           │
│        │     (ECDH + HKDF)             │     (ECDH + HKDF)                  │
│        │                               │                                    │
│        ▼                               ▼                                    │
│   ┌──────────┐                    ┌──────────┐                              │
│   │  Shared  │ ════════════════  │  Shared  │  (Identical on both sides)   │
│   │  Secret  │                    │  Secret  │                              │
│   └──────────┘                    └──────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           MEDIA FLOW PHASE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                         User A Device                            │      │
│   │  ┌────────┐    ┌─────────────┐    ┌──────────┐    ┌──────────┐  │      │
│   │  │ Camera │───►│ VP8/H264    │───►│ E2EE     │───►│ WebRTC   │  │      │
│   │  │  Mic   │    │ Opus Encode │    │ Encrypt  │    │ SRTP+DTLS│  │      │
│   │  └────────┘    └─────────────┘    │(AES-GCM) │    └────┬─────┘  │      │
│   │                                   │ ▲        │         │        │      │
│   │                                   │ │User Key│         │        │      │
│   │                                   └─┴────────┘         │        │      │
│   └────────────────────────────────────────────────────────┼────────┘      │
│                                                            │               │
│                              ┌─────────────────────────────┼───────┐       │
│                              │     Cloudflare TURN         │       │       │
│                              │                             ▼       │       │
│                              │   ┌─────────────────────────────┐   │       │
│                              │   │  Encrypted blob relay       │   │       │
│                              │   │  • Cannot see E2EE layer    │   │       │
│                              │   │  • Cannot see SRTP payload  │   │       │
│                              │   │  • Only routes packets      │   │       │
│                              │   └─────────────────────────────┘   │       │
│                              │                             │       │       │
│                              └─────────────────────────────┼───────┘       │
│                                                            │               │
│   ┌────────────────────────────────────────────────────────┼────────┐      │
│   │                         User B Device                  │        │      │
│   │  ┌────────┐    ┌─────────────┐    ┌──────────┐    ┌────▼─────┐  │      │
│   │  │ Screen │◄───│ VP8/H264    │◄───│ E2EE     │◄───│ WebRTC   │  │      │
│   │  │Speaker │    │ Opus Decode │    │ Decrypt  │    │ SRTP+DTLS│  │      │
│   │  └────────┘    └─────────────┘    │(AES-GCM) │    └──────────┘  │      │
│   │                                   │ ▲        │                  │      │
│   │                                   │ │User Key│                  │      │
│   │                                   └─┴────────┘                  │      │
│   └─────────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Encryption Layers

| Layer | What it protects against | Who controls keys |
|-------|-------------------------|-------------------|
| **Layer 1: Your E2EE (AES-GCM)** | Your servers, TURN servers, MITM | Users |
| **Layer 2: SRTP** | Network eavesdropping | Peers (auto-negotiated) |
| **Layer 3: DTLS** | Key exchange tampering | Peers (auto-negotiated) |

## Key Exchange Options

### Option A: ECDH Per-Call (Ephemeral Keys)

Most secure for forward secrecy—new keys each call.

```
Alice                          Vettid                           Bob
  │                              │                               │
  │──── call_init ──────────────►│                               │
  │     {to: "bob"}              │                               │
  │                              │──── incoming_call ───────────►│
  │                              │     {from: "alice"}           │
  │                              │                               │
  │                              │◄─── call_accept ─────────────│
  │◄─── call_accepted ──────────│     {publicKey: bob_ecdh_pub} │
  │     {publicKey: bob_ecdh_pub}│                               │
  │                              │                               │
  │──── key_exchange ───────────►│                               │
  │     {publicKey: alice_ecdh}  │──── key_exchange ────────────►│
  │                              │     {publicKey: alice_ecdh}   │
  │                              │                               │
  │  [Derive shared secret]      │     [Derive shared secret]    │
  │  [Start WebRTC w/ E2EE]      │     [Start WebRTC w/ E2EE]    │
```

### Option B: Pre-Shared User Keys (Persistent)

Users generate long-term keys, exchange out-of-band or via verified channel.

```
┌─────────────────────────────────────────────────────────────┐
│  User Settings / Key Management                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  My Public Key: [Copy to share]                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Trusted Contacts:                                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Bob (verified ✓)     [fingerprint: A3:4B:C2...]    │   │
│  │ Carol (unverified)   [fingerprint: 7F:E1:D9...]    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [Generate New Key Pair]  [Export Private Key (encrypted)] │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Option C: Hybrid (Recommended)

- Long-term identity keys for verification
- Ephemeral session keys for forward secrecy
- Similar to Signal Protocol's X3DH

---

## Implementation

### 1. Vettid Signaling Message Types

```typescript
// Add these message types to Vettid signaling protocol

interface E2EEKeyExchange {
  type: 'e2ee_key_exchange';
  callId: string;
  publicKey: string;        // Base64-encoded ECDH public key
  keyId: string;            // Unique identifier for key rotation
  identityKey?: string;     // Optional: long-term identity key for verification
  signature?: string;       // Optional: signature proving identity key ownership
}

interface E2EEKeyAck {
  type: 'e2ee_key_ack';
  callId: string;
  keyId: string;
  verified: boolean;        // Whether identity was verified against known key
}

interface E2EEKeyRotate {
  type: 'e2ee_key_rotate';
  callId: string;
  newPublicKey: string;
  keyId: string;
  epoch: number;            // Incrementing counter for key generations
}
```

### 2. Key Generation (Web Crypto API)

```typescript
// e2ee-crypto.ts

export class E2EECrypto {
  private keyPair: CryptoKeyPair | null = null;
  private sharedSecret: CryptoKey | null = null;
  private currentKeyId: string = '';

  /**
   * Generate ephemeral ECDH key pair for this call
   */
  async generateKeyPair(): Promise<{ publicKey: string; keyId: string }> {
    this.keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,  // extractable (needed to export public key)
      ['deriveKey', 'deriveBits']
    );

    // Export public key for sharing
    const publicKeyRaw = await crypto.subtle.exportKey(
      'spki',
      this.keyPair.publicKey
    );
    
    this.currentKeyId = crypto.randomUUID();
    
    return {
      publicKey: this.arrayBufferToBase64(publicKeyRaw),
      keyId: this.currentKeyId
    };
  }

  /**
   * Derive shared secret from peer's public key
   */
  async deriveSharedSecret(peerPublicKeyBase64: string): Promise<void> {
    if (!this.keyPair) {
      throw new Error('Must generate key pair first');
    }

    // Import peer's public key
    const peerPublicKeyRaw = this.base64ToArrayBuffer(peerPublicKeyBase64);
    const peerPublicKey = await crypto.subtle.importKey(
      'spki',
      peerPublicKeyRaw,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      false,
      []
    );

    // Derive shared secret using ECDH
    const sharedBits = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey
      },
      this.keyPair.privateKey,
      256
    );

    // Derive AES-GCM key using HKDF
    const sharedKeyMaterial = await crypto.subtle.importKey(
      'raw',
      sharedBits,
      'HKDF',
      false,
      ['deriveKey']
    );

    this.sharedSecret = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('webrtc-e2ee-v1'),
        info: new TextEncoder().encode('media-encryption')
      },
      sharedKeyMaterial,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a media frame
   */
  async encryptFrame(frame: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.sharedSecret) {
      throw new Error('Shared secret not established');
    }

    // Generate random IV for each frame
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      this.sharedSecret,
      frame
    );

    // Prepend IV to ciphertext
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);
    
    return result.buffer;
  }

  /**
   * Decrypt a media frame
   */
  async decryptFrame(encryptedFrame: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.sharedSecret) {
      throw new Error('Shared secret not established');
    }

    const data = new Uint8Array(encryptedFrame);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    return await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      this.sharedSecret,
      ciphertext
    );
  }

  // Utility methods
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
```

### 3. Insertable Streams Integration

```typescript
// e2ee-transform.ts

import { E2EECrypto } from './e2ee-crypto';

export class E2EETransform {
  private crypto: E2EECrypto;
  private encoder = new TextEncoder();

  constructor(crypto: E2EECrypto) {
    this.crypto = crypto;
  }

  /**
   * Create sender transform for RTCRtpSender
   */
  createSenderTransform(): TransformStream {
    const crypto = this.crypto;
    
    return new TransformStream({
      async transform(encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, controller) {
        try {
          // Get the frame data
          const frameData = encodedFrame.data;
          
          // Encrypt the frame
          const encryptedData = await crypto.encryptFrame(frameData);
          
          // Replace frame data with encrypted version
          encodedFrame.data = encryptedData;
          
          controller.enqueue(encodedFrame);
        } catch (error) {
          console.error('Encryption failed:', error);
          // Drop frame on encryption failure
        }
      }
    });
  }

  /**
   * Create receiver transform for RTCRtpReceiver
   */
  createReceiverTransform(): TransformStream {
    const crypto = this.crypto;
    
    return new TransformStream({
      async transform(encodedFrame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, controller) {
        try {
          // Get the encrypted frame data
          const encryptedData = encodedFrame.data;
          
          // Decrypt the frame
          const decryptedData = await crypto.decryptFrame(encryptedData);
          
          // Replace frame data with decrypted version
          encodedFrame.data = decryptedData;
          
          controller.enqueue(encodedFrame);
        } catch (error) {
          console.error('Decryption failed:', error);
          // Drop frame on decryption failure (expected during key rotation)
        }
      }
    });
  }
}
```

### 4. WebRTC Integration

```typescript
// e2ee-webrtc.ts

import { E2EECrypto } from './e2ee-crypto';
import { E2EETransform } from './e2ee-transform';

export class E2EEWebRTCCall {
  private peerConnection: RTCPeerConnection;
  private crypto: E2EECrypto;
  private transform: E2EETransform;
  private vettidSignaling: VettidSignaling;  // Your Vettid client

  constructor(vettidSignaling: VettidSignaling) {
    this.vettidSignaling = vettidSignaling;
    this.crypto = new E2EECrypto();
    this.transform = new E2EETransform(this.crypto);
    
    // ICE configuration with Cloudflare
    this.peerConnection = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.cloudflare.com:3478' },
        {
          urls: 'turn:turn.cloudflare.com:3478',
          username: 'YOUR_TURN_USERNAME',
          credential: 'YOUR_TURN_CREDENTIAL'
        }
      ],
      // Enable encoded transforms (Insertable Streams)
      encodedInsertableStreams: true
    } as RTCConfiguration);
  }

  /**
   * Initiate an E2EE call
   */
  async initiateCall(peerId: string): Promise<void> {
    // Step 1: Generate our key pair
    const { publicKey, keyId } = await this.crypto.generateKeyPair();
    
    // Step 2: Send key exchange via Vettid
    await this.vettidSignaling.send({
      type: 'e2ee_key_exchange',
      to: peerId,
      publicKey,
      keyId
    });

    // Step 3: Wait for peer's key
    const peerKeyExchange = await this.vettidSignaling.waitFor('e2ee_key_exchange');
    
    // Step 4: Derive shared secret
    await this.crypto.deriveSharedSecret(peerKeyExchange.publicKey);
    
    // Step 5: Now proceed with standard WebRTC setup
    await this.setupMediaWithE2EE();
  }

  /**
   * Set up media streams with E2EE transforms
   */
  private async setupMediaWithE2EE(): Promise<void> {
    // Get local media
    const stream = await navigator.mediaDevices.getUserMedia({
      video: true,
      audio: true
    });

    // Add tracks with E2EE transforms
    for (const track of stream.getTracks()) {
      const sender = this.peerConnection.addTrack(track, stream);
      
      // Apply sender transform (encryption)
      if ('transform' in sender) {
        (sender as any).transform = new RTCRtpScriptTransform(
          new Worker('e2ee-worker.js'),
          { operation: 'encrypt' }
        );
      } else if ('createEncodedStreams' in sender) {
        // Fallback for older API
        const { readable, writable } = (sender as any).createEncodedStreams();
        const transform = this.transform.createSenderTransform();
        readable.pipeThrough(transform).pipeTo(writable);
      }
    }

    // Handle incoming tracks
    this.peerConnection.ontrack = (event) => {
      const receiver = event.receiver;
      
      // Apply receiver transform (decryption)
      if ('transform' in receiver) {
        (receiver as any).transform = new RTCRtpScriptTransform(
          new Worker('e2ee-worker.js'),
          { operation: 'decrypt' }
        );
      } else if ('createEncodedStreams' in receiver) {
        const { readable, writable } = (receiver as any).createEncodedStreams();
        const transform = this.transform.createReceiverTransform();
        readable.pipeThrough(transform).pipeTo(writable);
      }
      
      // Display remote video
      const remoteVideo = document.getElementById('remoteVideo') as HTMLVideoElement;
      if (remoteVideo.srcObject !== event.streams[0]) {
        remoteVideo.srcObject = event.streams[0];
      }
    };
  }
}
```

### 5. Worker for RTCRtpScriptTransform (Modern API)

```javascript
// e2ee-worker.js

// This runs in a dedicated worker for better performance
// and works with RTCRtpScriptTransform (standards-track API)

let sharedKey = null;

// Receive shared key from main thread
self.onmessage = async (event) => {
  if (event.data.type === 'setKey') {
    // Import the shared key
    sharedKey = await crypto.subtle.importKey(
      'raw',
      event.data.keyData,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }
};

// Handle encoded frames
onrtctransform = async (event) => {
  const transformer = event.transformer;
  const readable = transformer.readable;
  const writable = transformer.writable;
  const operation = transformer.options.operation;

  const transformStream = new TransformStream({
    async transform(frame, controller) {
      if (!sharedKey) {
        // No key yet, pass through (or drop)
        controller.enqueue(frame);
        return;
      }

      try {
        if (operation === 'encrypt') {
          // Encrypt outgoing frame
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            frame.data
          );
          
          // Combine IV + ciphertext
          const combined = new Uint8Array(12 + encrypted.byteLength);
          combined.set(iv);
          combined.set(new Uint8Array(encrypted), 12);
          
          frame.data = combined.buffer;
        } else {
          // Decrypt incoming frame
          const data = new Uint8Array(frame.data);
          const iv = data.slice(0, 12);
          const ciphertext = data.slice(12);
          
          const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            ciphertext
          );
          
          frame.data = decrypted;
        }
        
        controller.enqueue(frame);
      } catch (error) {
        // Drop corrupted frames silently
        // This is expected during key rotation
      }
    }
  });

  readable.pipeThrough(transformStream).pipeTo(writable);
};
```

---

## Mobile Implementation Notes

### iOS (Swift)

```swift
// Use WebRTC.framework's RTCFrameCryptor for native E2EE
import WebRTC

class E2EEManager {
    private var frameCryptor: RTCFrameCryptor?
    
    func setupEncryption(sender: RTCRtpSender, key: Data) {
        let keyProvider = RTCFrameCryptorKeyProvider()
        keyProvider.setKey(key, withIndex: 0, forParticipant: "local")
        
        frameCryptor = RTCFrameCryptor(
            factory: peerConnectionFactory,
            rtpSender: sender,
            participantId: "local",
            algorithm: .aesGcm,
            keyProvider: keyProvider
        )
        frameCryptor?.enabled = true
    }
}
```

### Android (Kotlin)

```kotlin
// Use libwebrtc's FrameCryptor API
import org.webrtc.FrameCryptor
import org.webrtc.FrameCryptorKeyProvider

class E2EEManager {
    private var frameCryptor: FrameCryptor? = null
    
    fun setupEncryption(sender: RtpSender, key: ByteArray) {
        val keyProvider = FrameCryptorKeyProvider()
        keyProvider.setKey("local", 0, key)
        
        frameCryptor = FrameCryptor.create(
            peerConnectionFactory,
            sender,
            "local",
            FrameCryptor.Algorithm.AES_GCM,
            keyProvider
        )
        frameCryptor?.enabled = true
    }
}
```

---

## Security Considerations

### Key Verification

To prevent MITM attacks through Vettid:

1. **Safety Numbers**: Display a hash of both public keys for users to verify out-of-band
2. **QR Code Exchange**: For in-person verification
3. **Trusted Contacts**: Remember verified keys for future calls

```typescript
function generateSafetyNumber(aliceKey: string, bobKey: string): string {
  const combined = [aliceKey, bobKey].sort().join('');
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(combined));
  // Format as readable chunks
  return Array.from(new Uint8Array(hash))
    .slice(0, 6)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

// Display: "Safety Number: A3:4B:C2:7F:E1:D9"
// Both users should see the same number
```

### Forward Secrecy

- Generate new ECDH keys for each call
- Old call recordings cannot be decrypted even if long-term keys are compromised
- Consider key ratcheting for long calls (new keys every N minutes)

### Key Storage (Mobile)

- iOS: Store private keys in Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Android: Store in Android Keystore with user authentication required

---

## Summary

| Component | Technology | Who Controls |
|-----------|------------|--------------|
| Signaling | Vettid | You |
| Key Exchange | ECDH via Vettid | Users |
| Frame Encryption | AES-256-GCM | Users |
| ICE/STUN | Cloudflare (free) | Cloudflare |
| TURN Relay | Cloudflare ($0.05/GB) | Cloudflare |
| Transport Encryption | DTLS-SRTP | Peers (auto) |

**Result**: Triple-layered encryption where users control the innermost layer, making the content opaque to all intermediaries including Vettid and Cloudflare.
