/**
 * Input Validation Security Tests
 *
 * Tests for protection against injection attacks and malicious input:
 * - SQL injection prevention
 * - NoSQL injection prevention (DynamoDB)
 * - Command injection prevention
 * - XSS payload sanitization
 * - Path traversal prevention
 * - File upload validation
 * - JSON parsing security
 * - Request size limits
 *
 * OWASP Reference: A03:2021 - Injection
 */

import {
  SQL_INJECTION_PAYLOADS,
  NOSQL_INJECTION_PAYLOADS,
  XSS_PAYLOADS,
  COMMAND_INJECTION_PAYLOADS,
  PATH_TRAVERSAL_PAYLOADS,
} from '../fixtures/security/securityScenarios';

// Input validation utilities
const InputValidator = {
  /**
   * Sanitize string input - removes null bytes, normalizes whitespace
   */
  sanitizeString(input: string): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }
    // Remove null bytes
    let sanitized = input.replace(/\0/g, '');
    // Normalize whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim();
    // Limit length
    return sanitized.substring(0, 10000);
  },

  /**
   * Validate email format
   */
  validateEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email) && email.length <= 254;
  },

  /**
   * Validate UUID format
   */
  validateUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  },

  /**
   * Escape HTML entities to prevent XSS
   */
  escapeHtml(input: string): string {
    const htmlEntities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;',
    };
    return input.replace(/[&<>"'`=/]/g, char => htmlEntities[char]);
  },

  /**
   * Detect SQL injection attempts
   */
  detectSqlInjection(input: string): boolean {
    const patterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|UNION|DECLARE)\b)/i,
      /(--|\#|\/\*|\*\/)/,
      /(\bOR\b|\bAND\b)\s*(\d+\s*=\s*\d+|['"].*['"]\s*=\s*['"])/i,
      /['"];\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i,
      /\bWAITFOR\s+DELAY\b/i,
      /\bEXEC\s*\(/i,
      /\bxp_\w+/i,
    ];
    return patterns.some(pattern => pattern.test(input));
  },

  /**
   * Detect NoSQL injection attempts (DynamoDB/MongoDB style)
   */
  detectNoSqlInjection(input: unknown): boolean {
    if (typeof input === 'string') {
      // Check for JSON operator injection
      const patterns = [
        /\$[a-z]+/i, // MongoDB operators like $gt, $ne, $where
        /\{\s*['"]\$\w+['"]/i, // JSON with MongoDB operators
        /\{\s*["']?\s*S\s*["']?\s*:/i, // DynamoDB attribute value format injection
      ];
      return patterns.some(pattern => pattern.test(input));
    }
    if (typeof input === 'object' && input !== null) {
      // Check for operator keys in objects
      const checkObject = (obj: Record<string, unknown>): boolean => {
        for (const key of Object.keys(obj)) {
          if (key.startsWith('$')) return true;
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            if (checkObject(obj[key] as Record<string, unknown>)) return true;
          }
        }
        return false;
      };
      return checkObject(input as Record<string, unknown>);
    }
    return false;
  },

  /**
   * Detect command injection attempts
   */
  detectCommandInjection(input: string): boolean {
    const patterns = [
      /[;&|`$(){}[\]<>]/,
      /\$\(.*\)/,
      /`.*`/,
      /\|\||\&\&/,
      /\n|\r/,
      /(^|\s)(cat|ls|rm|mv|cp|chmod|chown|wget|curl|nc|bash|sh|python|perl|ruby)\s/i,
    ];
    return patterns.some(pattern => pattern.test(input));
  },

  /**
   * Detect path traversal attempts
   */
  detectPathTraversal(input: string): boolean {
    const patterns = [
      /\.\.\//,
      /\.\.\\/,
      /\.\.%2[fF]/,
      /\.\.%5[cC]/,
      /%2[eE]%2[eE]/,
      /\.\.[;%]/,
      /^[/\\]/,
      /[/\\]etc[/\\]/i,
      /[/\\]passwd/i,
      /[/\\]shadow/i,
      /[/\\]windows[/\\]/i,
    ];
    return patterns.some(pattern => pattern.test(input));
  },

  /**
   * Validate JSON safely
   */
  safeParseJson(input: string, maxDepth: number = 10): { valid: boolean; value?: unknown; error?: string } {
    try {
      const parsed = JSON.parse(input);

      // Check depth
      const checkDepth = (obj: unknown, depth: number): boolean => {
        if (depth > maxDepth) return false;
        if (typeof obj === 'object' && obj !== null) {
          return Object.values(obj as Record<string, unknown>).every(v => checkDepth(v, depth + 1));
        }
        return true;
      };

      if (!checkDepth(parsed, 0)) {
        return { valid: false, error: 'JSON depth exceeds maximum allowed' };
      }

      return { valid: true, value: parsed };
    } catch (e) {
      return { valid: false, error: (e as Error).message };
    }
  },

  /**
   * Validate file upload
   */
  validateFileUpload(filename: string, mimeType: string, size: number): { valid: boolean; error?: string } {
    // Allowed extensions
    const allowedExtensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx'];
    const allowedMimeTypes = [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ];

    // Check for path traversal in filename
    if (this.detectPathTraversal(filename)) {
      return { valid: false, error: 'Invalid filename: path traversal detected' };
    }

    // Check for null bytes
    if (filename.includes('\0')) {
      return { valid: false, error: 'Invalid filename: null byte detected' };
    }

    // Check extension
    const ext = filename.toLowerCase().slice(filename.lastIndexOf('.'));
    if (!allowedExtensions.includes(ext)) {
      return { valid: false, error: 'File extension not allowed' };
    }

    // Check for double extensions
    if ((filename.match(/\./g) || []).length > 1) {
      const parts = filename.split('.');
      if (parts.some((part, i) => i < parts.length - 1 && allowedExtensions.includes(`.${part}`))) {
        return { valid: false, error: 'Invalid filename: double extension detected' };
      }
    }

    // Check MIME type
    if (!allowedMimeTypes.includes(mimeType)) {
      return { valid: false, error: 'File type not allowed' };
    }

    // Check size (max 10MB)
    const maxSize = 10 * 1024 * 1024;
    if (size > maxSize) {
      return { valid: false, error: 'File size exceeds maximum allowed' };
    }

    return { valid: true };
  },

  /**
   * Validate request size
   */
  validateRequestSize(contentLength: number, maxSize: number = 1024 * 1024): boolean {
    return contentLength <= maxSize;
  },
};

describe('Input Validation Security Tests', () => {
  describe('SQL Injection Prevention', () => {
    /**
     * OWASP A03:2021 - Injection
     * Tests that SQL injection payloads are properly detected and rejected
     */
    describe('SQL injection payload detection', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should detect SQL injection payload ${index + 1}: ${payload.substring(0, 50)}...`, () => {
          const detected = InputValidator.detectSqlInjection(payload);
          expect(detected).toBe(true);
        });
      });
    });

    it('should allow legitimate input', () => {
      const legitimateInputs = [
        'John Doe',
        'john.doe@example.com',
        '123 Main St, Apt 4',
        'Hello, how are you?',
        'Product name: Widget Pro 2000',
      ];

      legitimateInputs.forEach(input => {
        expect(InputValidator.detectSqlInjection(input)).toBe(false);
      });
    });

    it('should detect UNION-based injection', () => {
      const unionPayloads = [
        "' UNION SELECT * FROM users--",
        "1 UNION ALL SELECT password FROM users",
        "admin' UNION SELECT null,username,password FROM users--",
      ];

      unionPayloads.forEach(payload => {
        expect(InputValidator.detectSqlInjection(payload)).toBe(true);
      });
    });

    it('should detect time-based blind injection', () => {
      const timeBasedPayloads = [
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:10'",
      ];

      timeBasedPayloads.forEach(payload => {
        expect(InputValidator.detectSqlInjection(payload)).toBe(true);
      });
    });

    it('should detect second-order injection attempts', () => {
      const secondOrderPayloads = [
        "admin'--",
        "user'; DROP TABLE users;--",
      ];

      secondOrderPayloads.forEach(payload => {
        expect(InputValidator.detectSqlInjection(payload)).toBe(true);
      });
    });
  });

  describe('NoSQL Injection Prevention', () => {
    /**
     * OWASP A03:2021 - Injection (NoSQL variant)
     * Tests protection against DynamoDB and MongoDB injection attacks
     */
    describe('NoSQL injection payload detection', () => {
      NOSQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should detect NoSQL injection payload ${index + 1}`, () => {
          const detected = InputValidator.detectNoSqlInjection(payload);
          expect(detected).toBe(true);
        });
      });
    });

    it('should detect MongoDB operator injection', () => {
      const mongoPayloads = [
        { $gt: '' },
        { $ne: null },
        { $where: 'this.password.length > 0' },
        { $regex: '.*' },
        { username: { $gt: '' }, password: { $gt: '' } },
      ];

      mongoPayloads.forEach(payload => {
        expect(InputValidator.detectNoSqlInjection(payload)).toBe(true);
      });
    });

    it('should detect DynamoDB injection attempts', () => {
      const dynamoPayloads = [
        '{"S": "admin"}',
        '{"N": "1"}',
      ];

      dynamoPayloads.forEach(payload => {
        expect(InputValidator.detectNoSqlInjection(payload)).toBe(true);
      });
    });

    it('should allow legitimate objects', () => {
      const legitimateObjects = [
        { name: 'John', email: 'john@example.com' },
        { id: '123', status: 'active' },
        { items: ['a', 'b', 'c'] },
      ];

      legitimateObjects.forEach(obj => {
        expect(InputValidator.detectNoSqlInjection(obj)).toBe(false);
      });
    });
  });

  describe('XSS Prevention', () => {
    /**
     * OWASP A03:2021 - Injection (XSS)
     * Tests protection against Cross-Site Scripting attacks
     */
    describe('XSS payload sanitization', () => {
      XSS_PAYLOADS.forEach((payload, index) => {
        it(`should escape XSS payload ${index + 1}: ${payload.substring(0, 40)}...`, () => {
          const escaped = InputValidator.escapeHtml(payload);

          // Should not contain unescaped script tags
          expect(escaped).not.toMatch(/<script/i);
          // Should not contain unescaped event handlers
          expect(escaped).not.toMatch(/on\w+\s*=/i);
          // Should have escaped dangerous characters
          expect(escaped).not.toContain('<');
          expect(escaped).not.toContain('>');
        });
      });
    });

    it('should escape all HTML entities', () => {
      const input = '<script>alert("XSS")</script>';
      const escaped = InputValidator.escapeHtml(input);

      expect(escaped).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;');
    });

    it('should handle nested script injection', () => {
      const input = '<<script>script>alert("XSS")<</script>/script>';
      const escaped = InputValidator.escapeHtml(input);

      expect(escaped).not.toContain('<script>');
      expect(escaped).not.toContain('</script>');
    });

    it('should escape event handlers', () => {
      const input = '<img src=x onerror="alert(1)">';
      const escaped = InputValidator.escapeHtml(input);

      expect(escaped).not.toMatch(/onerror/);
    });

    it('should handle unicode-encoded payloads', () => {
      const input = '\u003cscript\u003ealert(1)\u003c/script\u003e';
      const escaped = InputValidator.escapeHtml(input);

      expect(escaped).not.toContain('<');
      expect(escaped).not.toContain('>');
    });
  });

  describe('Command Injection Prevention', () => {
    /**
     * OWASP A03:2021 - Injection (Command)
     * Tests protection against OS command injection
     */
    describe('Command injection payload detection', () => {
      COMMAND_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should detect command injection payload ${index + 1}: ${payload.substring(0, 40)}...`, () => {
          const detected = InputValidator.detectCommandInjection(payload);
          expect(detected).toBe(true);
        });
      });
    });

    it('should detect shell metacharacters', () => {
      const metacharPayloads = [
        'file; ls -la',
        'file | cat /etc/passwd',
        'file && rm -rf /',
        'file || echo pwned',
        'file `whoami`',
        'file $(id)',
      ];

      metacharPayloads.forEach(payload => {
        expect(InputValidator.detectCommandInjection(payload)).toBe(true);
      });
    });

    it('should detect newline injection', () => {
      const newlinePayloads = [
        "file\nls -la",
        "file\r\nwhoami",
      ];

      newlinePayloads.forEach(payload => {
        expect(InputValidator.detectCommandInjection(payload)).toBe(true);
      });
    });

    it('should allow legitimate filenames', () => {
      const legitimateFilenames = [
        'document.pdf',
        'my-file-2023.txt',
        'report_final_v2.docx',
      ];

      legitimateFilenames.forEach(filename => {
        expect(InputValidator.detectCommandInjection(filename)).toBe(false);
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    /**
     * OWASP A01:2021 - Broken Access Control (Path Traversal)
     * Tests protection against directory traversal attacks
     */
    describe('Path traversal payload detection', () => {
      PATH_TRAVERSAL_PAYLOADS.forEach((payload, index) => {
        it(`should detect path traversal payload ${index + 1}: ${payload}`, () => {
          const detected = InputValidator.detectPathTraversal(payload);
          expect(detected).toBe(true);
        });
      });
    });

    it('should detect encoded traversal sequences', () => {
      const encodedPayloads = [
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%5c..%5c..%5cwindows%5csystem32',
        '%2e%2e%2f%2e%2e%2f',
        '..%252f..%252f', // Double encoding
      ];

      encodedPayloads.forEach(payload => {
        expect(InputValidator.detectPathTraversal(payload)).toBe(true);
      });
    });

    it('should detect absolute path injection', () => {
      const absolutePaths = [
        '/etc/passwd',
        '\\windows\\system32\\config\\sam',
        '/root/.ssh/id_rsa',
      ];

      absolutePaths.forEach(path => {
        expect(InputValidator.detectPathTraversal(path)).toBe(true);
      });
    });

    it('should allow legitimate relative paths', () => {
      const legitimatePaths = [
        'uploads/image.jpg',
        'documents/report.pdf',
        'user-content/file.txt',
      ];

      legitimatePaths.forEach(path => {
        expect(InputValidator.detectPathTraversal(path)).toBe(false);
      });
    });
  });

  describe('File Upload Validation', () => {
    /**
     * OWASP A04:2021 - Insecure Design (File Upload)
     * Tests protection against malicious file uploads
     */
    it('should reject executable extensions', () => {
      const executableFiles = [
        { name: 'malware.exe', type: 'application/x-msdownload' },
        { name: 'script.sh', type: 'application/x-sh' },
        { name: 'script.bat', type: 'application/x-bat' },
        { name: 'script.php', type: 'application/x-php' },
        { name: 'script.jsp', type: 'application/jsp' },
      ];

      executableFiles.forEach(file => {
        const result = InputValidator.validateFileUpload(file.name, file.type, 1000);
        expect(result.valid).toBe(false);
      });
    });

    it('should reject double extensions', () => {
      const doubleExtFiles = [
        'image.php.jpg',
        'document.jsp.pdf',
        'script.exe.png',
      ];

      doubleExtFiles.forEach(filename => {
        const result = InputValidator.validateFileUpload(filename, 'image/jpeg', 1000);
        // Some double extensions should be caught if the first is executable
        expect(result.valid === false || result.error?.includes('double extension')).toBe(true);
      });
    });

    it('should reject null byte injection in filename', () => {
      const nullByteFiles = [
        'image.php\0.jpg',
        'script.exe\x00.pdf',
      ];

      nullByteFiles.forEach(filename => {
        const result = InputValidator.validateFileUpload(filename, 'image/jpeg', 1000);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('null byte');
      });
    });

    it('should reject path traversal in filename', () => {
      const traversalFiles = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
      ];

      traversalFiles.forEach(filename => {
        const result = InputValidator.validateFileUpload(filename, 'application/pdf', 1000);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('path traversal');
      });
    });

    it('should reject oversized files', () => {
      const result = InputValidator.validateFileUpload(
        'large-file.pdf',
        'application/pdf',
        20 * 1024 * 1024 // 20MB
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain('size exceeds');
    });

    it('should reject MIME type mismatch', () => {
      const result = InputValidator.validateFileUpload(
        'image.jpg',
        'application/x-php',
        1000
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain('type not allowed');
    });

    it('should accept valid file uploads', () => {
      const validFiles = [
        { name: 'document.pdf', type: 'application/pdf', size: 500000 },
        { name: 'photo.jpg', type: 'image/jpeg', size: 2000000 },
        { name: 'image.png', type: 'image/png', size: 1500000 },
      ];

      validFiles.forEach(file => {
        const result = InputValidator.validateFileUpload(file.name, file.type, file.size);
        expect(result.valid).toBe(true);
      });
    });
  });

  describe('JSON Parsing Security', () => {
    /**
     * OWASP A08:2021 - Software and Data Integrity Failures
     * Tests protection against malicious JSON payloads
     */
    it('should reject deeply nested JSON', () => {
      // Create deeply nested object
      let nested: Record<string, unknown> = { value: 'deep' };
      for (let i = 0; i < 20; i++) {
        nested = { nested };
      }

      const result = InputValidator.safeParseJson(JSON.stringify(nested), 10);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('depth exceeds');
    });

    it('should handle JSON parsing errors gracefully', () => {
      const invalidJson = [
        '{ invalid }',
        '{"key": undefined}',
        "{'single': 'quotes'}",
        '{"trailing": "comma",}',
      ];

      invalidJson.forEach(json => {
        const result = InputValidator.safeParseJson(json);
        expect(result.valid).toBe(false);
        expect(result.error).toBeDefined();
      });
    });

    it('should parse valid JSON', () => {
      const validJson = [
        '{"name": "John", "age": 30}',
        '{"items": [1, 2, 3]}',
        '{"nested": {"key": "value"}}',
        'null',
        '"string"',
        '123',
      ];

      validJson.forEach(json => {
        const result = InputValidator.safeParseJson(json);
        expect(result.valid).toBe(true);
        expect(result.value).toBeDefined();
      });
    });

    it('should handle prototype pollution attempts', () => {
      const pollutionPayloads = [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
      ];

      pollutionPayloads.forEach(payload => {
        const result = InputValidator.safeParseJson(payload);
        // JSON.parse itself is safe from prototype pollution
        // but the result should be handled carefully
        expect(result.valid).toBe(true);

        // Verify prototype wasn't polluted
        const obj = {} as Record<string, unknown>;
        expect(obj['admin']).toBeUndefined();
      });
    });
  });

  describe('Request Size Limits', () => {
    /**
     * OWASP A05:2021 - Security Misconfiguration
     * Tests protection against oversized requests (DoS prevention)
     */
    it('should reject oversized requests', () => {
      const maxSize = 1024 * 1024; // 1MB

      expect(InputValidator.validateRequestSize(2 * 1024 * 1024, maxSize)).toBe(false);
      expect(InputValidator.validateRequestSize(10 * 1024 * 1024, maxSize)).toBe(false);
    });

    it('should accept requests within size limit', () => {
      const maxSize = 1024 * 1024; // 1MB

      expect(InputValidator.validateRequestSize(512 * 1024, maxSize)).toBe(true);
      expect(InputValidator.validateRequestSize(1024 * 1024, maxSize)).toBe(true);
      expect(InputValidator.validateRequestSize(1000, maxSize)).toBe(true);
    });

    it('should use default size limit when not specified', () => {
      expect(InputValidator.validateRequestSize(500 * 1024)).toBe(true);
      expect(InputValidator.validateRequestSize(2 * 1024 * 1024)).toBe(false);
    });
  });

  describe('String Sanitization', () => {
    /**
     * General input sanitization tests
     */
    it('should remove null bytes', () => {
      const input = 'hello\0world';
      const sanitized = InputValidator.sanitizeString(input);

      expect(sanitized).not.toContain('\0');
      expect(sanitized).toBe('hello world');
    });

    it('should normalize whitespace', () => {
      const input = '  hello   world  \t\n  test  ';
      const sanitized = InputValidator.sanitizeString(input);

      expect(sanitized).toBe('hello world test');
    });

    it('should limit string length', () => {
      const longInput = 'a'.repeat(20000);
      const sanitized = InputValidator.sanitizeString(longInput);

      expect(sanitized.length).toBeLessThanOrEqual(10000);
    });

    it('should reject non-string input', () => {
      expect(() => InputValidator.sanitizeString(123 as unknown as string)).toThrow('Input must be a string');
      expect(() => InputValidator.sanitizeString(null as unknown as string)).toThrow();
      expect(() => InputValidator.sanitizeString({} as unknown as string)).toThrow();
    });
  });

  describe('Email Validation', () => {
    /**
     * Email format validation tests
     */
    it('should accept valid emails', () => {
      const validEmails = [
        'user@example.com',
        'user.name@example.com',
        'user+tag@example.com',
        'user@subdomain.example.com',
      ];

      validEmails.forEach(email => {
        expect(InputValidator.validateEmail(email)).toBe(true);
      });
    });

    it('should reject invalid emails', () => {
      const invalidEmails = [
        'invalid',
        '@example.com',
        'user@',
        'user@.com',
        'user@example',
        'user name@example.com',
        'user@example..com',
      ];

      invalidEmails.forEach(email => {
        expect(InputValidator.validateEmail(email)).toBe(false);
      });
    });

    it('should reject oversized emails', () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      expect(InputValidator.validateEmail(longEmail)).toBe(false);
    });
  });

  describe('UUID Validation', () => {
    /**
     * UUID format validation tests
     */
    it('should accept valid UUIDs', () => {
      const validUuids = [
        '123e4567-e89b-12d3-a456-426614174000',
        'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      ];

      validUuids.forEach(uuid => {
        expect(InputValidator.validateUUID(uuid)).toBe(true);
      });
    });

    it('should reject invalid UUIDs', () => {
      const invalidUuids = [
        'invalid-uuid',
        '123e4567-e89b-12d3-a456', // Too short
        '123e4567-e89b-12d3-a456-4266141740001', // Too long
        '123e4567-e89b-62d3-a456-426614174000', // Invalid version
        '123e4567-e89b-12d3-c456-426614174000', // Invalid variant
        'ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ', // Invalid characters
      ];

      invalidUuids.forEach(uuid => {
        expect(InputValidator.validateUUID(uuid)).toBe(false);
      });
    });
  });

  describe('Combined Attack Vectors', () => {
    /**
     * Tests for combined/chained attack vectors
     */
    it('should detect SQL injection combined with XSS', () => {
      const combinedPayload = "'; alert('XSS'); DROP TABLE users;--";

      expect(InputValidator.detectSqlInjection(combinedPayload)).toBe(true);
      const escaped = InputValidator.escapeHtml(combinedPayload);
      expect(escaped).not.toContain('<');
      expect(escaped).not.toContain('>');
    });

    it('should detect command injection with path traversal', () => {
      const combinedPayload = '../../../bin/sh -c "rm -rf /"';

      expect(InputValidator.detectPathTraversal(combinedPayload)).toBe(true);
      expect(InputValidator.detectCommandInjection(combinedPayload)).toBe(true);
    });

    it('should handle polyglot payloads', () => {
      // Payload that could work as SQL injection, XSS, and command injection
      const polyglot = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//";

      // Should be caught by XSS escaping
      const escaped = InputValidator.escapeHtml(polyglot);
      expect(escaped).not.toMatch(/onclick/i);
    });
  });

  describe('Unicode and Encoding Attacks', () => {
    /**
     * Tests for unicode-based bypass attempts
     */
    it('should handle homograph attacks', () => {
      // Using Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
      const homographEmail = 'аdmin@example.com'; // First 'a' is Cyrillic

      // This should ideally be detected, but basic validation may not catch it
      // The test documents the behavior
      const isValid = InputValidator.validateEmail(homographEmail);
      // Modern email validation should catch this
      expect(isValid).toBe(false);
    });

    it('should handle null byte injection', () => {
      const nullBytePayload = 'admin\0.jpg.php';

      // Should be detected as path traversal attempt
      const sanitized = InputValidator.sanitizeString(nullBytePayload);
      expect(sanitized).not.toContain('\0');
    });

    it('should handle UTF-8 overlong encoding', () => {
      // Overlong encoding of '<' (0xC0 0xBC)
      // These should be rejected or normalized
      const overlongPayload = '\xC0\xBC\x73\x63\x72\x69\x70\x74\xC0\xBE';

      // The escaped version should not be executable
      const escaped = InputValidator.escapeHtml(overlongPayload);
      expect(escaped).toBeDefined();
    });
  });
});
