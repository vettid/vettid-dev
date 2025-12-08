/**
 * Security Configuration Module - Phase 9 Security Hardening
 *
 * Centralized security configuration for the VettID application.
 * This module defines security policies, allowed values, and validation rules.
 */

/**
 * Password policy configuration
 */
export const PASSWORD_POLICY = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  // Characters that must be present for special char requirement
  specialChars: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
  // Passwords must not contain these patterns
  forbiddenPatterns: [
    /(.)\1{2,}/,      // No more than 2 repeated characters
    /password/i,      // No "password"
    /vettid/i,        // No "vettid"
    /123456/,         // No sequential numbers
    /qwerty/i,        // No keyboard patterns
  ],
  // Maximum age in days (0 = no expiration)
  maxAgeDays: 0,
  // Minimum age before change (prevent rapid changes)
  minAgeDays: 0,
  // Number of previous passwords to remember
  historyCount: 5,
};

/**
 * Session policy configuration
 */
export const SESSION_POLICY = {
  // Access token lifetime in seconds
  accessTokenLifetimeSeconds: 3600, // 1 hour
  // Refresh token lifetime in seconds
  refreshTokenLifetimeSeconds: 30 * 24 * 3600, // 30 days
  // Idle timeout in seconds (0 = no idle timeout)
  idleTimeoutSeconds: 1800, // 30 minutes
  // Maximum concurrent sessions per user (0 = unlimited)
  maxConcurrentSessions: 5,
  // Require re-authentication for sensitive operations
  sensitiveOperationReauthSeconds: 300, // 5 minutes
  // Session binding options
  bindToIp: false,       // Bind session to IP (can cause issues with mobile)
  bindToUserAgent: true, // Bind session to user agent
};

/**
 * PIN policy configuration
 */
export const PIN_POLICY = {
  minLength: 4,
  maxLength: 6,
  maxAttempts: 5,
  lockoutDurationSeconds: 900, // 15 minutes
  // Weak PIN patterns that are not allowed (defined in util.ts isWeakPin)
};

/**
 * API rate limit configuration
 */
export const API_RATE_LIMITS = {
  // Default limits (requests per minute)
  default: {
    anonymous: 60,
    authenticated: 120,
    admin: 300,
  },
  // Endpoint-specific limits
  endpoints: {
    "/register": { anonymous: 3, windowMinutes: 60 },
    "/waitlist": { anonymous: 5, windowMinutes: 60 },
    "/vault/enroll": { authenticated: 10, windowMinutes: 60 },
    "/vault/auth": { authenticated: 10, windowMinutes: 60 },
    "/vault/backup": { authenticated: 5, windowMinutes: 60 },
    "/admin/*": { admin: 100, windowMinutes: 60 },
  },
};

/**
 * CORS configuration
 */
export const CORS_CONFIG = {
  // Allowed origins (should match environment configuration)
  allowedOrigins: [
    "https://vettid.dev",
    "https://www.vettid.dev",
    "https://admin.vettid.dev",
    "https://account.vettid.dev",
    "https://register.vettid.dev",
  ],
  // Development origins (should be disabled in production)
  developmentOrigins: [
    "http://localhost:3000",
    "http://localhost:5173",
  ],
  // Allowed methods
  allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  // Allowed headers
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Request-Signature",
    "X-Request-Timestamp",
    "X-Request-Nonce",
  ],
  // Exposed headers (headers that can be accessed by client)
  exposedHeaders: [
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "Retry-After",
  ],
  // Preflight cache duration in seconds
  maxAge: 86400, // 24 hours
  // Allow credentials (cookies, authorization headers)
  allowCredentials: true,
};

/**
 * Content Security Policy configuration
 */
export const CSP_CONFIG = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'", "'unsafe-inline'"], // unsafe-inline needed for some UI frameworks
  "img-src": ["'self'", "data:", "https:"],
  "font-src": ["'self'"],
  "connect-src": ["'self'", "https://*.vettid.dev"],
  "frame-ancestors": ["'none'"],
  "form-action": ["'self'"],
  "base-uri": ["'self'"],
  "object-src": ["'none'"],
};

/**
 * Build CSP header string
 */
export function buildCSPHeader(): string {
  return Object.entries(CSP_CONFIG)
    .map(([directive, sources]) => `${directive} ${sources.join(" ")}`)
    .join("; ");
}

/**
 * Cryptographic configuration
 */
export const CRYPTO_CONFIG = {
  // Key derivation (Argon2id)
  argon2: {
    memoryCost: 65536,     // 64 MB
    timeCost: 3,           // 3 iterations
    parallelism: 4,        // 4 parallel threads
    hashLength: 32,        // 256 bits
    saltLength: 16,        // 128 bits
  },
  // Encryption (XChaCha20-Poly1305)
  xchacha20: {
    keyLength: 32,         // 256 bits
    nonceLength: 24,       // 192 bits
    tagLength: 16,         // 128 bits
  },
  // Key exchange (X25519)
  x25519: {
    keyLength: 32,         // 256 bits
  },
  // Signing (Ed25519)
  ed25519: {
    signatureLength: 64,   // 512 bits
  },
  // HMAC (SHA-256)
  hmac: {
    algorithm: "sha256",
    keyLength: 32,         // 256 bits
  },
};

/**
 * Backup configuration
 */
export const BACKUP_CONFIG = {
  // Maximum backup size in bytes
  maxBackupSizeBytes: 100 * 1024 * 1024, // 100 MB
  // Maximum backups per user
  maxBackupsPerUser: 50,
  // Retention policy
  retention: {
    dailyBackups: 7,      // Keep last 7 daily backups
    weeklyBackups: 4,     // Keep last 4 weekly backups
    monthlyBackups: 12,   // Keep last 12 monthly backups
  },
  // Auto-backup settings
  autoBackup: {
    defaultEnabled: true,
    defaultFrequency: "daily",
    defaultTimeUtc: "03:00",
  },
};

/**
 * Audit logging configuration
 */
export const AUDIT_CONFIG = {
  // Events that should always be logged
  alwaysLog: [
    "login",
    "logout",
    "password_change",
    "pin_change",
    "enrollment_complete",
    "backup_create",
    "backup_restore",
    "credential_backup",
    "credential_recover",
    "connection_create",
    "connection_revoke",
    "admin_action",
  ],
  // Events that should be logged only on failure
  logOnFailure: [
    "authentication",
    "authorization",
    "rate_limit",
    "input_validation",
  ],
  // Retention period in days
  retentionDays: 90,
  // PII masking rules
  maskFields: [
    "password",
    "pin",
    "recovery_phrase",
    "private_key",
    "secret",
    "token",
    "credential",
  ],
};

/**
 * Security headers configuration
 */
export const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
  "Pragma": "no-cache",
};

/**
 * Input validation limits
 */
export const INPUT_LIMITS = {
  // Field-specific limits
  email: { maxLength: 254 },
  name: { minLength: 1, maxLength: 100 },
  inviteCode: { minLength: 3, maxLength: 50 },
  bio: { maxLength: 500 },
  message: { maxLength: 10000 },
  handler_id: { maxLength: 64 },
  backup_id: { maxLength: 64 },
  // Default limits
  defaultString: { minLength: 1, maxLength: 1000 },
  // Request body limit
  maxRequestBodyBytes: 1024 * 1024, // 1 MB
};

/**
 * Suspicious patterns to detect in inputs
 */
export const SUSPICIOUS_PATTERNS = {
  // SQL injection
  sql: [
    /('|"|;|--|\/\*|\*\/|xp_|sp_|union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set)/i,
  ],
  // NoSQL injection
  nosql: [
    /(\$where|\$ne|\$gt|\$lt|\$regex|\$in|\$nin|\$or|\$and|{\s*"\$)/i,
  ],
  // Command injection
  command: [
    /(;|\||`|\$\(|&&|\|\||>|<|eval\(|exec\(|system\()/i,
  ],
  // XSS
  xss: [
    /<script[\s\S]*?>/i,
    /\bon\w+\s*=/i,
    /javascript:/i,
    /data:text\/html/i,
  ],
  // Path traversal
  pathTraversal: [
    /\.\.\//,
    /%2e%2e%2f/i,
    /%252e%252e%252f/i,
  ],
};

/**
 * Allowed file types for uploads
 */
export const ALLOWED_FILE_TYPES = {
  images: ["image/jpeg", "image/png", "image/gif", "image/webp"],
  documents: ["application/pdf", "text/plain"],
  handlers: ["application/wasm"],
};

/**
 * Feature flags for security features
 */
export const SECURITY_FEATURES = {
  // Request signing validation
  requestSigning: {
    enabled: process.env.ENABLE_REQUEST_SIGNING === "true",
    required: process.env.REQUIRE_REQUEST_SIGNING === "true",
  },
  // Rate limiting
  rateLimiting: {
    enabled: process.env.DISABLE_RATE_LIMITING !== "true",
  },
  // Brute force protection
  bruteForceProtection: {
    enabled: process.env.DISABLE_BRUTE_FORCE_PROTECTION !== "true",
  },
  // CORS validation
  corsValidation: {
    enabled: process.env.DISABLE_CORS_VALIDATION !== "true",
    allowDevelopmentOrigins: process.env.NODE_ENV !== "production",
  },
  // Security event logging
  securityEventLogging: {
    enabled: process.env.DISABLE_SECURITY_LOGGING !== "true",
  },
};

/**
 * Get effective CORS origins based on environment
 */
export function getEffectiveCorsOrigins(): string[] {
  if (SECURITY_FEATURES.corsValidation.allowDevelopmentOrigins) {
    return [...CORS_CONFIG.allowedOrigins, ...CORS_CONFIG.developmentOrigins];
  }
  return CORS_CONFIG.allowedOrigins;
}

/**
 * Validate password against policy
 */
export function validatePasswordPolicy(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (password.length < PASSWORD_POLICY.minLength) {
    errors.push(`Password must be at least ${PASSWORD_POLICY.minLength} characters`);
  }

  if (password.length > PASSWORD_POLICY.maxLength) {
    errors.push(`Password must be at most ${PASSWORD_POLICY.maxLength} characters`);
  }

  if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }

  if (PASSWORD_POLICY.requireNumbers && !/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }

  if (PASSWORD_POLICY.requireSpecialChars) {
    const specialCharRegex = new RegExp(`[${PASSWORD_POLICY.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`);
    if (!specialCharRegex.test(password)) {
      errors.push("Password must contain at least one special character");
    }
  }

  for (const pattern of PASSWORD_POLICY.forbiddenPatterns) {
    if (pattern.test(password)) {
      errors.push("Password contains a forbidden pattern");
      break;
    }
  }

  return { valid: errors.length === 0, errors };
}
