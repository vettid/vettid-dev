/**
 * @vettid/shared-utils
 * Shared utilities for VettID Lambda functions
 *
 * This layer provides common functionality used across Lambda handlers:
 * - AWS SDK clients (DynamoDB, SES, Cognito)
 * - HTTP response helpers with CORS
 * - User claims extraction and validation
 * - Input validation and sanitization
 * - Rate limiting
 * - Audit logging
 */

export * from './clients';
export * from './responses';
export * from './auth';
export * from './validation';
export * from './security';
export * from './helpers';
