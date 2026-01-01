/**
 * Password hashing utilities using Argon2id
 *
 * This module contains ONLY password hashing functions that require
 * the argon2 native module. Split from crypto.ts to allow Lambdas
 * that don't need password hashing to avoid bundling native deps.
 *
 * IMPORTANT: Only import this module in Lambdas that actually need
 * password hashing (verifyPassword, createCredential, etc.)
 *
 * @see cdk/coordination/specs/credential-format.md
 */

import { timingSafeEqual } from 'crypto';
import argon2 from 'argon2';

// ============================================
// Password Hashing (Argon2id)
// ============================================

/**
 * Argon2id parameters matching OWASP 2024 recommendations
 * These values provide strong security while remaining usable on Lambda
 *
 * SECURITY NOTE: 64MB memory cost is the OWASP 2024 minimum recommendation.
 * Higher values (e.g., 256MB) would increase GPU-cracking resistance but:
 * - Require Lambda memory increases (512MB+ headroom needed)
 * - Could fail on low-memory mobile devices
 * - Must stay consistent across Lambda/Android/iOS platforms
 *
 * Cross-platform consistency is critical - mobile apps use the same parameters.
 * @see Android: CryptoManager.kt ARGON2_MEMORY_KB = 65536
 * @see iOS: PasswordHasher.swift MemLimitModerate (~64MB)
 */
const ARGON2_PARAMS = {
  type: argon2.argon2id,
  timeCost: 3,          // 3 iterations (OWASP minimum: 3)
  memoryCost: 65536,    // 64 MB (OWASP minimum: 64 MB)
  parallelism: 4,       // 4 threads (note: iOS libsodium uses 1 internally)
  hashLength: 32,       // 32-byte output (256 bits)
};

// Validate Argon2 parameters meet minimum security requirements
function validateArgon2Params(): void {
  if (ARGON2_PARAMS.memoryCost < 65536) {
    throw new Error('CRITICAL: Argon2 memory cost too low (min: 64 MB / 65536 KB)');
  }
  if (ARGON2_PARAMS.timeCost < 3) {
    throw new Error('CRITICAL: Argon2 time cost too low (min: 3 iterations)');
  }
  if (ARGON2_PARAMS.parallelism < 1) {
    throw new Error('CRITICAL: Argon2 parallelism must be at least 1');
  }
  if (ARGON2_PARAMS.hashLength < 32) {
    throw new Error('CRITICAL: Argon2 hash length too short (min: 32 bytes)');
  }
}

// Validate on module load to fail fast
validateArgon2Params();

/**
 * Hash password using Argon2id
 *
 * Argon2id is the recommended algorithm for password hashing as it provides
 * resistance against both GPU cracking attacks (Argon2i) and side-channel
 * attacks (Argon2d).
 *
 * @param password Plain text password
 * @returns PHC-formatted hash string (e.g., $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>)
 */
export async function hashPassword(password: string): Promise<string> {
  // argon2 library automatically generates a 16-byte salt if not provided
  const hash = await argon2.hash(password, {
    type: ARGON2_PARAMS.type,
    memoryCost: ARGON2_PARAMS.memoryCost,
    timeCost: ARGON2_PARAMS.timeCost,
    parallelism: ARGON2_PARAMS.parallelism,
    hashLength: ARGON2_PARAMS.hashLength,
  });

  return hash;
}

/**
 * Verify password against stored hash
 *
 * Supports both Argon2id and legacy PBKDF2 hashes for migration purposes.
 * New hashes should always use Argon2id.
 *
 * @param storedHash PHC-formatted hash string
 * @param password Plain text password to verify
 * @returns true if password matches
 */
export async function verifyPassword(storedHash: string, password: string): Promise<boolean> {
  // Argon2id format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
  if (storedHash.startsWith('$argon2')) {
    return await argon2.verify(storedHash, password);
  }

  // Legacy PBKDF2 format for migration: $pbkdf2-sha256$i=100000$<salt>$<hash>
  const parts = storedHash.split('$').filter(Boolean);
  if (parts[0] === 'pbkdf2-sha256') {
    const iterations = parseInt(parts[1].replace('i=', ''), 10);
    const salt = Buffer.from(parts[2], 'base64');
    const expectedHash = Buffer.from(parts[3], 'base64');

    const { pbkdf2Sync } = await import('crypto');
    const computedHash = pbkdf2Sync(password, salt, iterations, expectedHash.length, 'sha256');

    return timingSafeEqual(computedHash, expectedHash);
  }

  throw new Error(`Unsupported hash format: ${parts[0]}`);
}

/**
 * Check if a hash needs to be upgraded to Argon2id
 * Used for transparent migration of legacy PBKDF2 hashes
 *
 * @param storedHash PHC-formatted hash string
 * @returns true if hash should be rehashed with Argon2id
 */
export function needsRehash(storedHash: string): boolean {
  return !storedHash.startsWith('$argon2id');
}
