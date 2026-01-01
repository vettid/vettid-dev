/**
 * Input validation and sanitization helpers
 */

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Validate UUID format (with or without hyphens)
 */
export function isValidUUID(uuid: string): boolean {
  return /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(uuid);
}

/**
 * Validate VettID GUID format (user-XXXXX or guid-XXXXX)
 */
export function isValidGuid(guid: string): boolean {
  if (!guid) return false;
  const uuidPart = guid.replace(/^(user|guid|invite|connection)-/i, '');
  return isValidUUID(uuidPart);
}

/**
 * Require valid GUID or throw ValidationError
 */
export function requireValidGuid(guid: string, fieldName = 'guid'): void {
  if (!isValidGuid(guid)) {
    throw new ValidationError(`Invalid ${fieldName} format`);
  }
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Require valid email or throw ValidationError
 */
export function requireValidEmail(email: string): void {
  if (!isValidEmail(email)) {
    throw new ValidationError('Invalid email format');
  }
}

/**
 * Sanitize string input - trim and limit length
 */
export function sanitizeString(input: string, maxLength = 1000): string {
  if (typeof input !== 'string') {
    return '';
  }
  return input.trim().substring(0, maxLength);
}

/**
 * Parse and validate JSON body from API Gateway event
 */
export function parseBody<T>(body: string | null): T {
  if (!body) {
    throw new ValidationError('Request body is required');
  }
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new ValidationError('Invalid JSON in request body');
  }
}
