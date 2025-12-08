/**
 * Error Handling Integration Tests
 *
 * Phase 10: Production Readiness & Polish
 *
 * Comprehensive tests for error handling across all API endpoints
 * ensuring user-friendly error messages, proper error codes, and
 * no sensitive information leakage.
 */

import * as crypto from 'crypto';

// ============================================================================
// Mock Error Handler Service
// ============================================================================

interface ErrorResponse {
  statusCode: number;
  body: {
    error: string;
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  headers: Record<string, string>;
}

interface ErrorCategory {
  code: string;
  httpStatus: number;
  userMessage: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  retryable: boolean;
}

const ERROR_CATEGORIES: Record<string, ErrorCategory> = {
  VALIDATION_ERROR: {
    code: 'VALIDATION_ERROR',
    httpStatus: 400,
    userMessage: 'Invalid request parameters',
    logLevel: 'info',
    retryable: false,
  },
  AUTHENTICATION_ERROR: {
    code: 'AUTHENTICATION_ERROR',
    httpStatus: 401,
    userMessage: 'Authentication required',
    logLevel: 'warn',
    retryable: false,
  },
  AUTHORIZATION_ERROR: {
    code: 'AUTHORIZATION_ERROR',
    httpStatus: 403,
    userMessage: 'Access denied',
    logLevel: 'warn',
    retryable: false,
  },
  NOT_FOUND_ERROR: {
    code: 'NOT_FOUND_ERROR',
    httpStatus: 404,
    userMessage: 'Resource not found',
    logLevel: 'info',
    retryable: false,
  },
  CONFLICT_ERROR: {
    code: 'CONFLICT_ERROR',
    httpStatus: 409,
    userMessage: 'Resource conflict',
    logLevel: 'info',
    retryable: false,
  },
  RATE_LIMIT_ERROR: {
    code: 'RATE_LIMIT_ERROR',
    httpStatus: 429,
    userMessage: 'Too many requests',
    logLevel: 'warn',
    retryable: true,
  },
  INTERNAL_ERROR: {
    code: 'INTERNAL_ERROR',
    httpStatus: 500,
    userMessage: 'An unexpected error occurred',
    logLevel: 'error',
    retryable: true,
  },
  SERVICE_UNAVAILABLE: {
    code: 'SERVICE_UNAVAILABLE',
    httpStatus: 503,
    userMessage: 'Service temporarily unavailable',
    logLevel: 'error',
    retryable: true,
  },
};

class MockErrorHandler {
  private sensitivePatterns: RegExp[] = [
    /password/i,
    /secret/i,
    /token/i,
    /key/i,
    /credential/i,
    /aws[_-]?access/i,
    /aws[_-]?secret/i,
    /api[_-]?key/i,
    /bearer\s+\S+/i,
    /\b[A-Za-z0-9+/]{40,}={0,2}\b/, // Base64 encoded strings (likely secrets)
    /\bAKIA[A-Z0-9]{16}\b/, // AWS Access Key ID pattern
    /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d+:[a-z0-9-/]+/i, // AWS ARN pattern
  ];

  private stackTracePattern = /at\s+[\w$.]+\s+\([^)]+:\d+:\d+\)/;

  sanitizeError(error: Error | string): string {
    let message = typeof error === 'string' ? error : error.message;

    // Remove stack traces
    message = message.replace(this.stackTracePattern, '[REDACTED]');

    // Remove sensitive data
    for (const pattern of this.sensitivePatterns) {
      message = message.replace(pattern, '[REDACTED]');
    }

    return message;
  }

  formatErrorResponse(
    category: keyof typeof ERROR_CATEGORIES,
    details?: string
  ): ErrorResponse {
    const errorDef = ERROR_CATEGORIES[category];

    return {
      statusCode: errorDef.httpStatus,
      body: {
        error: category,
        code: errorDef.code,
        message: details ? this.sanitizeError(details) : errorDef.userMessage,
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Error-Code': errorDef.code,
        'Cache-Control': 'no-store',
      },
    };
  }

  containsSensitiveInfo(text: string): boolean {
    for (const pattern of this.sensitivePatterns) {
      if (pattern.test(text)) {
        return true;
      }
    }
    return false;
  }

  containsStackTrace(text: string): boolean {
    return this.stackTracePattern.test(text);
  }
}

// ============================================================================
// Mock API Service for Error Testing
// ============================================================================

interface APIRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: unknown;
  query?: Record<string, string>;
}

class MockAPIService {
  private errorHandler = new MockErrorHandler();
  private requestCount = 0;
  private rateLimitWindow = 60000; // 1 minute
  private rateLimitMax = 100;
  private requestTimestamps: number[] = [];

  async handleRequest(request: APIRequest): Promise<ErrorResponse | { statusCode: number; body: unknown }> {
    // Check rate limit
    if (this.isRateLimited()) {
      return this.errorHandler.formatErrorResponse('RATE_LIMIT_ERROR', 'Please try again later');
    }

    try {
      // Validate request
      const validationError = this.validateRequest(request);
      if (validationError) {
        return validationError;
      }

      // Check authentication
      const authError = this.checkAuthentication(request);
      if (authError) {
        return authError;
      }

      // Check authorization
      const authzError = this.checkAuthorization(request);
      if (authzError) {
        return authzError;
      }

      // Route to handler
      return this.routeRequest(request);
    } catch (error) {
      // Catch all unexpected errors
      return this.handleUnexpectedError(error);
    }
  }

  private isRateLimited(): boolean {
    const now = Date.now();
    this.requestTimestamps = this.requestTimestamps.filter(
      ts => now - ts < this.rateLimitWindow
    );
    this.requestTimestamps.push(now);
    return this.requestTimestamps.length > this.rateLimitMax;
  }

  private validateRequest(request: APIRequest): ErrorResponse | null {
    // Check method
    if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
      return this.errorHandler.formatErrorResponse(
        'VALIDATION_ERROR',
        'Invalid HTTP method'
      );
    }

    // Check content type for body requests
    if (request.body && !request.headers['content-type']?.includes('application/json')) {
      return this.errorHandler.formatErrorResponse(
        'VALIDATION_ERROR',
        'Content-Type must be application/json'
      );
    }

    // Validate body is valid JSON
    if (request.body && typeof request.body === 'string') {
      try {
        JSON.parse(request.body);
      } catch {
        return this.errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Invalid JSON in request body'
        );
      }
    }

    return null;
  }

  private checkAuthentication(request: APIRequest): ErrorResponse | null {
    // Skip auth for public endpoints
    if (request.path.startsWith('/public/')) {
      return null;
    }

    const authHeader = request.headers['authorization'];
    if (!authHeader) {
      return this.errorHandler.formatErrorResponse(
        'AUTHENTICATION_ERROR',
        'Missing authorization header'
      );
    }

    if (!authHeader.startsWith('Bearer ')) {
      return this.errorHandler.formatErrorResponse(
        'AUTHENTICATION_ERROR',
        'Invalid authorization format'
      );
    }

    const token = authHeader.substring(7);
    if (!this.isValidToken(token)) {
      return this.errorHandler.formatErrorResponse(
        'AUTHENTICATION_ERROR',
        'Invalid or expired token'
      );
    }

    return null;
  }

  private isValidToken(token: string): boolean {
    // Mock token validation - in reality this would verify JWT
    return token.length > 10 && !token.includes('invalid') && !token.includes('expired');
  }

  private checkAuthorization(request: APIRequest): ErrorResponse | null {
    // Admin endpoints require admin role
    if (request.path.startsWith('/admin/')) {
      const token = request.headers['authorization']?.substring(7) || '';
      if (!token.includes('admin')) {
        return this.errorHandler.formatErrorResponse(
          'AUTHORIZATION_ERROR',
          'Admin access required'
        );
      }
    }

    return null;
  }

  private routeRequest(request: APIRequest): ErrorResponse | { statusCode: number; body: unknown } {
    // Simulate various endpoint responses
    if (request.path.includes('/not-found')) {
      return this.errorHandler.formatErrorResponse(
        'NOT_FOUND_ERROR',
        'The requested resource does not exist'
      );
    }

    if (request.path.includes('/conflict')) {
      return this.errorHandler.formatErrorResponse(
        'CONFLICT_ERROR',
        'Resource already exists'
      );
    }

    if (request.path.includes('/error')) {
      throw new Error('Simulated internal error with secret_key=abc123');
    }

    return {
      statusCode: 200,
      body: { success: true },
    };
  }

  private handleUnexpectedError(error: unknown): ErrorResponse {
    // Log the full error internally (would go to CloudWatch)
    console.error('Internal error:', error);

    // Return sanitized error to user
    return this.errorHandler.formatErrorResponse(
      'INTERNAL_ERROR',
      'An unexpected error occurred. Please try again later.'
    );
  }

  // For testing rate limiting
  simulateRequests(count: number): void {
    const now = Date.now();
    for (let i = 0; i < count; i++) {
      this.requestTimestamps.push(now);
    }
  }

  resetRateLimit(): void {
    this.requestTimestamps = [];
  }
}

// ============================================================================
// Test Suites
// ============================================================================

describe('Error Handling Integration Tests', () => {
  let errorHandler: MockErrorHandler;
  let apiService: MockAPIService;

  beforeEach(() => {
    errorHandler = new MockErrorHandler();
    apiService = new MockAPIService();
  });

  describe('Error Sanitization', () => {
    describe('Sensitive Data Removal', () => {
      test('should redact password from error messages', () => {
        const error = 'Failed to authenticate with password=secret123';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('password=secret123');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should redact API keys from error messages', () => {
        const error = 'Request failed with api_key=sk_live_abc123def456';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('api_key=sk_live_abc123def456');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should redact AWS credentials from error messages', () => {
        const error = 'AWS error: aws_access_key_id=AKIAIOSFODNN7EXAMPLE';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should redact bearer tokens from error messages', () => {
        const error = 'Authorization failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should redact AWS ARNs from error messages', () => {
        const error = 'Access denied to arn:aws:dynamodb:us-east-1:123456789012:table/users';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('arn:aws:dynamodb:us-east-1:123456789012:table/users');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should redact secret keys from error messages', () => {
        const error = 'Encryption failed with secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should handle multiple sensitive values in one message', () => {
        const error = 'Failed: password=abc123, api_key=xyz789, token=jwt_here';
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('password=abc123');
        expect(sanitized).not.toContain('api_key=xyz789');
        expect(sanitized).not.toContain('token=jwt_here');
        expect(sanitized.match(/\[REDACTED\]/g)?.length).toBeGreaterThanOrEqual(3);
      });
    });

    describe('Stack Trace Removal', () => {
      test('should redact stack traces from error messages', () => {
        const error = `Error occurred at handleRequest (/app/src/handler.ts:42:15)`;
        const sanitized = errorHandler.sanitizeError(error);

        expect(sanitized).not.toContain('/app/src/handler.ts:42:15');
        expect(sanitized).toContain('[REDACTED]');
      });

      test('should detect stack traces', () => {
        const withStackTrace = 'Error at processRequest (file.js:10:20)';
        const withoutStackTrace = 'Error: Something went wrong';

        expect(errorHandler.containsStackTrace(withStackTrace)).toBe(true);
        expect(errorHandler.containsStackTrace(withoutStackTrace)).toBe(false);
      });
    });

    describe('Sensitive Information Detection', () => {
      test('should detect password in text', () => {
        expect(errorHandler.containsSensitiveInfo('password=test')).toBe(true);
        expect(errorHandler.containsSensitiveInfo('PASSWORD=test')).toBe(true);
      });

      test('should detect API keys in text', () => {
        expect(errorHandler.containsSensitiveInfo('api_key=test')).toBe(true);
        expect(errorHandler.containsSensitiveInfo('apiKey=test')).toBe(true);
      });

      test('should detect tokens in text', () => {
        expect(errorHandler.containsSensitiveInfo('token=abc')).toBe(true);
        expect(errorHandler.containsSensitiveInfo('Bearer xyz')).toBe(true);
      });

      test('should not flag normal text', () => {
        expect(errorHandler.containsSensitiveInfo('User not found')).toBe(false);
        expect(errorHandler.containsSensitiveInfo('Invalid input')).toBe(false);
      });
    });
  });

  describe('Error Response Formatting', () => {
    describe('Validation Errors (400)', () => {
      test('should return 400 for validation errors', () => {
        const response = errorHandler.formatErrorResponse('VALIDATION_ERROR');

        expect(response.statusCode).toBe(400);
        expect(response.body.code).toBe('VALIDATION_ERROR');
        expect(response.body.message).toBe('Invalid request parameters');
      });

      test('should include custom message when provided', () => {
        const response = errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Email format is invalid'
        );

        expect(response.body.message).toBe('Email format is invalid');
      });

      test('should set no-store cache control', () => {
        const response = errorHandler.formatErrorResponse('VALIDATION_ERROR');

        expect(response.headers['Cache-Control']).toBe('no-store');
      });
    });

    describe('Authentication Errors (401)', () => {
      test('should return 401 for authentication errors', () => {
        const response = errorHandler.formatErrorResponse('AUTHENTICATION_ERROR');

        expect(response.statusCode).toBe(401);
        expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        expect(response.body.message).toBe('Authentication required');
      });

      test('should not expose token details', () => {
        const response = errorHandler.formatErrorResponse(
          'AUTHENTICATION_ERROR',
          'Token validation failed with secret_key=abc123'
        );

        expect(response.body.message).not.toContain('secret_key=abc123');
        expect(response.body.message).toContain('[REDACTED]');
      });
    });

    describe('Authorization Errors (403)', () => {
      test('should return 403 for authorization errors', () => {
        const response = errorHandler.formatErrorResponse('AUTHORIZATION_ERROR');

        expect(response.statusCode).toBe(403);
        expect(response.body.code).toBe('AUTHORIZATION_ERROR');
        expect(response.body.message).toBe('Access denied');
      });
    });

    describe('Not Found Errors (404)', () => {
      test('should return 404 for not found errors', () => {
        const response = errorHandler.formatErrorResponse('NOT_FOUND_ERROR');

        expect(response.statusCode).toBe(404);
        expect(response.body.code).toBe('NOT_FOUND_ERROR');
        expect(response.body.message).toBe('Resource not found');
      });
    });

    describe('Conflict Errors (409)', () => {
      test('should return 409 for conflict errors', () => {
        const response = errorHandler.formatErrorResponse('CONFLICT_ERROR');

        expect(response.statusCode).toBe(409);
        expect(response.body.code).toBe('CONFLICT_ERROR');
      });
    });

    describe('Rate Limit Errors (429)', () => {
      test('should return 429 for rate limit errors', () => {
        const response = errorHandler.formatErrorResponse('RATE_LIMIT_ERROR');

        expect(response.statusCode).toBe(429);
        expect(response.body.code).toBe('RATE_LIMIT_ERROR');
        expect(response.body.message).toBe('Too many requests');
      });
    });

    describe('Internal Errors (500)', () => {
      test('should return 500 for internal errors', () => {
        const response = errorHandler.formatErrorResponse('INTERNAL_ERROR');

        expect(response.statusCode).toBe(500);
        expect(response.body.code).toBe('INTERNAL_ERROR');
        expect(response.body.message).toBe('An unexpected error occurred');
      });

      test('should never expose internal details', () => {
        const response = errorHandler.formatErrorResponse(
          'INTERNAL_ERROR',
          'Database error at /db/connection.ts:50:10 with password=dbpass'
        );

        expect(response.body.message).not.toContain('/db/connection.ts');
        expect(response.body.message).not.toContain('password=dbpass');
      });
    });

    describe('Service Unavailable Errors (503)', () => {
      test('should return 503 for service unavailable errors', () => {
        const response = errorHandler.formatErrorResponse('SERVICE_UNAVAILABLE');

        expect(response.statusCode).toBe(503);
        expect(response.body.code).toBe('SERVICE_UNAVAILABLE');
      });
    });
  });

  describe('API Error Handling', () => {
    describe('Request Validation', () => {
      test('should reject invalid HTTP methods', async () => {
        const response = await apiService.handleRequest({
          method: 'INVALID',
          path: '/api/test',
          headers: {},
        });

        expect(response.statusCode).toBe(400);
        expect((response as ErrorResponse).body.message).toContain('Invalid HTTP method');
      });

      test('should reject non-JSON content type for body requests', async () => {
        const response = await apiService.handleRequest({
          method: 'POST',
          path: '/public/test',
          headers: { 'content-type': 'text/plain' },
          body: 'test',
        });

        expect(response.statusCode).toBe(400);
        expect((response as ErrorResponse).body.message).toContain('Content-Type must be application/json');
      });

      test('should reject invalid JSON body', async () => {
        const response = await apiService.handleRequest({
          method: 'POST',
          path: '/public/test',
          headers: { 'content-type': 'application/json' },
          body: 'not valid json',
        });

        expect(response.statusCode).toBe(400);
        expect((response as ErrorResponse).body.message).toContain('Invalid JSON');
      });
    });

    describe('Authentication Errors', () => {
      test('should reject requests without authorization header', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/protected',
          headers: {},
        });

        expect(response.statusCode).toBe(401);
        expect((response as ErrorResponse).body.message).toContain('Missing authorization');
      });

      test('should reject invalid authorization format', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/protected',
          headers: { authorization: 'Basic abc123' },
        });

        expect(response.statusCode).toBe(401);
        expect((response as ErrorResponse).body.message).toContain('Invalid authorization format');
      });

      test('should reject invalid tokens', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/protected',
          headers: { authorization: 'Bearer invalid_token' },
        });

        expect(response.statusCode).toBe(401);
        expect((response as ErrorResponse).body.message).toContain('Invalid or expired token');
      });

      test('should reject expired tokens', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/protected',
          headers: { authorization: 'Bearer expired_token_here' },
        });

        expect(response.statusCode).toBe(401);
      });

      test('should allow requests to public endpoints without auth', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/public/health',
          headers: {},
        });

        expect(response.statusCode).toBe(200);
      });
    });

    describe('Authorization Errors', () => {
      test('should reject non-admin access to admin endpoints', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/admin/users',
          headers: { authorization: 'Bearer valid_user_token' },
        });

        expect(response.statusCode).toBe(403);
        expect((response as ErrorResponse).body.message).toContain('Admin access required');
      });

      test('should allow admin access to admin endpoints', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/admin/users',
          headers: { authorization: 'Bearer valid_admin_token' },
        });

        expect(response.statusCode).toBe(200);
      });
    });

    describe('Not Found Errors', () => {
      test('should return 404 for non-existent resources', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/not-found/resource',
          headers: { authorization: 'Bearer valid_user_token' },
        });

        expect(response.statusCode).toBe(404);
      });
    });

    describe('Conflict Errors', () => {
      test('should return 409 for resource conflicts', async () => {
        const response = await apiService.handleRequest({
          method: 'POST',
          path: '/api/conflict/create',
          headers: {
            authorization: 'Bearer valid_user_token',
            'content-type': 'application/json',
          },
          body: { name: 'test' },
        });

        expect(response.statusCode).toBe(409);
      });
    });

    describe('Rate Limiting', () => {
      test('should reject requests when rate limited', async () => {
        // Simulate hitting rate limit
        apiService.simulateRequests(101);

        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/public/test',
          headers: {},
        });

        expect(response.statusCode).toBe(429);
        expect((response as ErrorResponse).body.code).toBe('RATE_LIMIT_ERROR');
      });

      test('should allow requests after rate limit window', async () => {
        apiService.resetRateLimit();

        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/public/test',
          headers: {},
        });

        expect(response.statusCode).toBe(200);
      });
    });

    describe('Internal Error Handling', () => {
      test('should catch and sanitize unexpected errors', async () => {
        const response = await apiService.handleRequest({
          method: 'GET',
          path: '/api/error/trigger',
          headers: { authorization: 'Bearer valid_user_token' },
        });

        expect(response.statusCode).toBe(500);
        expect((response as ErrorResponse).body.message).not.toContain('secret_key');
        expect((response as ErrorResponse).body.message).toContain('unexpected error');
      });
    });
  });

  describe('Error Categories', () => {
    test('should have correct HTTP status for each category', () => {
      expect(ERROR_CATEGORIES.VALIDATION_ERROR.httpStatus).toBe(400);
      expect(ERROR_CATEGORIES.AUTHENTICATION_ERROR.httpStatus).toBe(401);
      expect(ERROR_CATEGORIES.AUTHORIZATION_ERROR.httpStatus).toBe(403);
      expect(ERROR_CATEGORIES.NOT_FOUND_ERROR.httpStatus).toBe(404);
      expect(ERROR_CATEGORIES.CONFLICT_ERROR.httpStatus).toBe(409);
      expect(ERROR_CATEGORIES.RATE_LIMIT_ERROR.httpStatus).toBe(429);
      expect(ERROR_CATEGORIES.INTERNAL_ERROR.httpStatus).toBe(500);
      expect(ERROR_CATEGORIES.SERVICE_UNAVAILABLE.httpStatus).toBe(503);
    });

    test('should identify retryable errors', () => {
      expect(ERROR_CATEGORIES.VALIDATION_ERROR.retryable).toBe(false);
      expect(ERROR_CATEGORIES.AUTHENTICATION_ERROR.retryable).toBe(false);
      expect(ERROR_CATEGORIES.RATE_LIMIT_ERROR.retryable).toBe(true);
      expect(ERROR_CATEGORIES.INTERNAL_ERROR.retryable).toBe(true);
      expect(ERROR_CATEGORIES.SERVICE_UNAVAILABLE.retryable).toBe(true);
    });

    test('should have appropriate log levels', () => {
      expect(ERROR_CATEGORIES.VALIDATION_ERROR.logLevel).toBe('info');
      expect(ERROR_CATEGORIES.AUTHENTICATION_ERROR.logLevel).toBe('warn');
      expect(ERROR_CATEGORIES.INTERNAL_ERROR.logLevel).toBe('error');
    });
  });

  describe('Cross-Cutting Error Scenarios', () => {
    describe('Enrollment Flow Errors', () => {
      test('should handle invalid invite code', () => {
        const response = errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Invalid invite code format'
        );

        expect(response.statusCode).toBe(400);
        expect(response.body.message).not.toContain('internal');
      });

      test('should handle expired invite code', () => {
        const response = errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Invite code has expired'
        );

        expect(response.statusCode).toBe(400);
      });

      test('should handle device attestation failure', () => {
        const response = errorHandler.formatErrorResponse(
          'AUTHENTICATION_ERROR',
          'Device attestation verification failed'
        );

        expect(response.statusCode).toBe(401);
      });
    });

    describe('Authentication Flow Errors', () => {
      test('should handle LAT expiration', () => {
        const response = errorHandler.formatErrorResponse(
          'AUTHENTICATION_ERROR',
          'Session has expired. Please re-authenticate.'
        );

        expect(response.statusCode).toBe(401);
        expect(response.body.message).toContain('expired');
      });

      test('should handle biometric verification failure', () => {
        const response = errorHandler.formatErrorResponse(
          'AUTHENTICATION_ERROR',
          'Biometric verification failed'
        );

        expect(response.statusCode).toBe(401);
      });
    });

    describe('Connection Flow Errors', () => {
      test('should handle invalid connection invitation', () => {
        const response = errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Invalid or expired connection invitation'
        );

        expect(response.statusCode).toBe(400);
      });

      test('should handle connection already exists', () => {
        const response = errorHandler.formatErrorResponse(
          'CONFLICT_ERROR',
          'Connection already established with this user'
        );

        expect(response.statusCode).toBe(409);
      });
    });

    describe('Messaging Flow Errors', () => {
      test('should handle recipient not found', () => {
        const response = errorHandler.formatErrorResponse(
          'NOT_FOUND_ERROR',
          'Recipient not found or connection revoked'
        );

        expect(response.statusCode).toBe(404);
      });

      test('should handle message encryption failure', () => {
        // Should not expose encryption details
        const response = errorHandler.formatErrorResponse(
          'INTERNAL_ERROR',
          'Failed to encrypt message with key=abc123'
        );

        expect(response.statusCode).toBe(500);
        expect(response.body.message).not.toContain('key=abc123');
      });
    });

    describe('Backup Flow Errors', () => {
      test('should handle backup decryption failure', () => {
        const response = errorHandler.formatErrorResponse(
          'VALIDATION_ERROR',
          'Invalid recovery phrase or corrupted backup'
        );

        expect(response.statusCode).toBe(400);
      });

      test('should handle backup not found', () => {
        const response = errorHandler.formatErrorResponse(
          'NOT_FOUND_ERROR',
          'Backup not found'
        );

        expect(response.statusCode).toBe(404);
      });
    });

    describe('Handler Execution Errors', () => {
      test('should handle handler timeout', () => {
        const response = errorHandler.formatErrorResponse(
          'SERVICE_UNAVAILABLE',
          'Handler execution timed out'
        );

        expect(response.statusCode).toBe(503);
      });

      test('should handle sandbox violation', () => {
        const response = errorHandler.formatErrorResponse(
          'AUTHORIZATION_ERROR',
          'Handler attempted unauthorized operation'
        );

        expect(response.statusCode).toBe(403);
      });
    });
  });

  describe('Error Message Consistency', () => {
    test('should use consistent error message format', () => {
      const categories = Object.keys(ERROR_CATEGORIES);

      for (const category of categories) {
        const response = errorHandler.formatErrorResponse(
          category as keyof typeof ERROR_CATEGORIES
        );

        // All responses should have these fields
        expect(response.body).toHaveProperty('error');
        expect(response.body).toHaveProperty('code');
        expect(response.body).toHaveProperty('message');

        // Error and code should match
        expect(response.body.error).toBe(category);
        expect(response.body.code).toBe(category);

        // Headers should be set
        expect(response.headers['Content-Type']).toBe('application/json');
        expect(response.headers['X-Error-Code']).toBe(category);
      }
    });

    test('should never include undefined in error messages', () => {
      const response = errorHandler.formatErrorResponse('VALIDATION_ERROR');

      expect(response.body.message).not.toContain('undefined');
      expect(response.body.message).not.toContain('null');
    });
  });
});

describe('Error Recovery Scenarios', () => {
  describe('Transient Error Handling', () => {
    test('should identify transient errors for retry logic', () => {
      const transientErrors = ['RATE_LIMIT_ERROR', 'INTERNAL_ERROR', 'SERVICE_UNAVAILABLE'];
      const permanentErrors = ['VALIDATION_ERROR', 'AUTHENTICATION_ERROR', 'AUTHORIZATION_ERROR', 'NOT_FOUND_ERROR'];

      for (const error of transientErrors) {
        expect(ERROR_CATEGORIES[error].retryable).toBe(true);
      }

      for (const error of permanentErrors) {
        expect(ERROR_CATEGORIES[error].retryable).toBe(false);
      }
    });
  });

  describe('Error Correlation', () => {
    test('should include error code in headers for correlation', () => {
      const errorHandler = new MockErrorHandler();
      const response = errorHandler.formatErrorResponse('INTERNAL_ERROR');

      expect(response.headers['X-Error-Code']).toBe('INTERNAL_ERROR');
    });
  });
});
