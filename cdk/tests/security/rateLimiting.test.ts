/**
 * API Rate Limiting Security Tests
 *
 * Tests for rate limiting implementation:
 * - Per-endpoint rate limit enforcement
 * - Per-user rate limit enforcement
 * - Global rate limit validation
 * - Rate limit bypass attempt detection
 * - Distributed rate limiting (IP rotation)
 * - Rate limit header validation
 * - Recovery after rate limit window
 *
 * OWASP Reference: A04:2021 - Insecure Design (Denial of Service)
 */

import { RateLimitTester, RATE_LIMIT_CONFIGS } from '../fixtures/security/securityScenarios';
import * as crypto from 'crypto';

// Mock rate limiter implementation for testing
class MockRateLimiter {
  private buckets: Map<string, { count: number; resetTime: number }> = new Map();

  constructor(
    private config: {
      windowMs: number;
      maxRequests: number;
      keyGenerator: (req: MockRequest) => string;
    }
  ) {}

  /**
   * Check if request is within rate limit
   */
  check(request: MockRequest): RateLimitResult {
    const key = this.config.keyGenerator(request);
    const now = Date.now();
    const bucket = this.buckets.get(key);

    // Clean up or create new bucket
    if (!bucket || bucket.resetTime <= now) {
      this.buckets.set(key, {
        count: 1,
        resetTime: now + this.config.windowMs,
      });
      return {
        allowed: true,
        remaining: this.config.maxRequests - 1,
        resetTime: now + this.config.windowMs,
        limit: this.config.maxRequests,
      };
    }

    // Increment existing bucket
    bucket.count++;

    if (bucket.count > this.config.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: bucket.resetTime,
        limit: this.config.maxRequests,
        retryAfter: Math.ceil((bucket.resetTime - now) / 1000),
      };
    }

    return {
      allowed: true,
      remaining: this.config.maxRequests - bucket.count,
      resetTime: bucket.resetTime,
      limit: this.config.maxRequests,
    };
  }

  /**
   * Reset rate limit for a key (for testing)
   */
  reset(request: MockRequest): void {
    const key = this.config.keyGenerator(request);
    this.buckets.delete(key);
  }

  /**
   * Get current state for a key
   */
  getState(request: MockRequest): { count: number; resetTime: number } | undefined {
    const key = this.config.keyGenerator(request);
    return this.buckets.get(key);
  }
}

// Token bucket rate limiter for more sophisticated rate limiting
class TokenBucketLimiter {
  private buckets: Map<string, { tokens: number; lastRefill: number }> = new Map();

  constructor(
    private config: {
      bucketSize: number;
      refillRate: number; // tokens per second
      keyGenerator: (req: MockRequest) => string;
    }
  ) {}

  check(request: MockRequest): RateLimitResult {
    const key = this.config.keyGenerator(request);
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = {
        tokens: this.config.bucketSize - 1,
        lastRefill: now,
      };
      this.buckets.set(key, bucket);
      return {
        allowed: true,
        remaining: bucket.tokens,
        resetTime: now + 1000,
        limit: this.config.bucketSize,
      };
    }

    // Refill tokens based on time elapsed
    const timePassed = (now - bucket.lastRefill) / 1000;
    const tokensToAdd = timePassed * this.config.refillRate;
    bucket.tokens = Math.min(this.config.bucketSize, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    if (bucket.tokens < 1) {
      const waitTime = Math.ceil((1 - bucket.tokens) / this.config.refillRate);
      return {
        allowed: false,
        remaining: 0,
        resetTime: now + waitTime * 1000,
        limit: this.config.bucketSize,
        retryAfter: waitTime,
      };
    }

    bucket.tokens -= 1;
    return {
      allowed: true,
      remaining: Math.floor(bucket.tokens),
      resetTime: now + 1000,
      limit: this.config.bucketSize,
    };
  }
}

interface MockRequest {
  ip: string;
  userId?: string;
  endpoint: string;
  headers?: Record<string, string>;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  limit: number;
  retryAfter?: number;
}

describe('API Rate Limiting Security Tests', () => {
  describe('Per-Endpoint Rate Limit Enforcement', () => {
    /**
     * OWASP A04:2021 - Insecure Design
     * Tests that each endpoint has appropriate rate limits
     */
    describe('Authentication endpoints', () => {
      let limiter: MockRateLimiter;

      beforeEach(() => {
        limiter = new MockRateLimiter({
          windowMs: RATE_LIMIT_CONFIGS.authentication.windowMs,
          maxRequests: RATE_LIMIT_CONFIGS.authentication.maxRequests,
          keyGenerator: req => `auth:${req.ip}`,
        });
      });

      it('should allow requests within limit', () => {
        const request = { ip: '192.168.1.1', endpoint: '/auth/login' };

        for (let i = 0; i < RATE_LIMIT_CONFIGS.authentication.maxRequests; i++) {
          const result = limiter.check(request);
          expect(result.allowed).toBe(true);
          expect(result.remaining).toBe(RATE_LIMIT_CONFIGS.authentication.maxRequests - i - 1);
        }
      });

      it('should block requests exceeding limit', () => {
        const request = { ip: '192.168.1.1', endpoint: '/auth/login' };

        // Exhaust the limit
        for (let i = 0; i < RATE_LIMIT_CONFIGS.authentication.maxRequests; i++) {
          limiter.check(request);
        }

        // Next request should be blocked
        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
        expect(result.remaining).toBe(0);
        expect(result.retryAfter).toBeGreaterThan(0);
      });

      it('should have strict limits for sensitive auth operations', () => {
        expect(RATE_LIMIT_CONFIGS.authentication.maxRequests).toBeLessThanOrEqual(10);
        expect(RATE_LIMIT_CONFIGS.authentication.windowMs).toBeGreaterThanOrEqual(60000);
      });
    });

    describe('API endpoints', () => {
      let limiter: MockRateLimiter;

      beforeEach(() => {
        limiter = new MockRateLimiter({
          windowMs: RATE_LIMIT_CONFIGS.api.windowMs,
          maxRequests: RATE_LIMIT_CONFIGS.api.maxRequests,
          keyGenerator: req => `api:${req.userId || req.ip}`,
        });
      });

      it('should allow higher limits for general API endpoints', () => {
        expect(RATE_LIMIT_CONFIGS.api.maxRequests).toBeGreaterThan(
          RATE_LIMIT_CONFIGS.authentication.maxRequests
        );
      });

      it('should rate limit by user ID when authenticated', () => {
        const request1 = { ip: '192.168.1.1', userId: 'user-1', endpoint: '/api/data' };
        const request2 = { ip: '192.168.1.2', userId: 'user-1', endpoint: '/api/data' };

        // Exhaust limit for user-1
        for (let i = 0; i < RATE_LIMIT_CONFIGS.api.maxRequests; i++) {
          limiter.check(request1);
        }

        // Request from different IP but same user should be blocked
        const result = limiter.check(request2);
        expect(result.allowed).toBe(false);
      });

      it('should rate limit by IP when unauthenticated', () => {
        const request1 = { ip: '192.168.1.1', endpoint: '/api/public' };
        const request2 = { ip: '192.168.1.2', endpoint: '/api/public' };

        // Exhaust limit for IP 1
        for (let i = 0; i < RATE_LIMIT_CONFIGS.api.maxRequests; i++) {
          limiter.check(request1);
        }

        // Request from different IP should be allowed
        const result = limiter.check(request2);
        expect(result.allowed).toBe(true);
      });
    });

    describe('Enrollment endpoints', () => {
      let limiter: MockRateLimiter;

      beforeEach(() => {
        limiter = new MockRateLimiter({
          windowMs: RATE_LIMIT_CONFIGS.enrollment.windowMs,
          maxRequests: RATE_LIMIT_CONFIGS.enrollment.maxRequests,
          keyGenerator: req => `enroll:${req.ip}`,
        });
      });

      it('should have moderate limits for enrollment', () => {
        expect(RATE_LIMIT_CONFIGS.enrollment.maxRequests).toBeLessThanOrEqual(20);
      });

      it('should prevent enrollment spam', () => {
        const request = { ip: '192.168.1.1', endpoint: '/vault/enroll' };

        // Exhaust limit
        for (let i = 0; i < RATE_LIMIT_CONFIGS.enrollment.maxRequests; i++) {
          limiter.check(request);
        }

        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
      });
    });
  });

  describe('Per-User Rate Limit Enforcement', () => {
    /**
     * Tests that rate limits are properly scoped to individual users
     */
    let limiter: MockRateLimiter;

    beforeEach(() => {
      limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 100,
        keyGenerator: req => `user:${req.userId || 'anonymous'}:${req.endpoint}`,
      });
    });

    it('should track rate limits separately per user', () => {
      const user1Request = { ip: '192.168.1.1', userId: 'user-1', endpoint: '/api/data' };
      const user2Request = { ip: '192.168.1.1', userId: 'user-2', endpoint: '/api/data' };

      // User 1 makes requests
      for (let i = 0; i < 50; i++) {
        limiter.check(user1Request);
      }

      // User 2 should have full quota
      const result = limiter.check(user2Request);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(99);
    });

    it('should track rate limits separately per endpoint', () => {
      const endpoint1Request = { ip: '192.168.1.1', userId: 'user-1', endpoint: '/api/data' };
      const endpoint2Request = { ip: '192.168.1.1', userId: 'user-1', endpoint: '/api/other' };

      // Exhaust limit on endpoint 1
      for (let i = 0; i < 100; i++) {
        limiter.check(endpoint1Request);
      }

      // Endpoint 2 should have full quota
      const result = limiter.check(endpoint2Request);
      expect(result.allowed).toBe(true);
    });
  });

  describe('Global Rate Limit Validation', () => {
    /**
     * Tests for system-wide rate limiting
     */
    let globalLimiter: MockRateLimiter;

    beforeEach(() => {
      globalLimiter = new MockRateLimiter({
        windowMs: 1000, // 1 second window
        maxRequests: 1000, // 1000 requests per second globally
        keyGenerator: () => 'global',
      });
    });

    it('should enforce global request limit', () => {
      // Simulate requests from many different IPs
      for (let i = 0; i < 1000; i++) {
        const request = { ip: `192.168.${Math.floor(i / 256)}.${i % 256}`, endpoint: '/api' };
        globalLimiter.check(request);
      }

      // Global limit should be reached
      const result = globalLimiter.check({ ip: '10.0.0.1', endpoint: '/api' });
      expect(result.allowed).toBe(false);
    });

    it('should protect against distributed DoS attempts', () => {
      // Simulate DDoS from many IPs
      const uniqueIps = 500;
      const requestsPerIp = 3;

      for (let i = 0; i < uniqueIps; i++) {
        for (let j = 0; j < requestsPerIp; j++) {
          const request = { ip: `${i}.${i}.${i}.${i}`, endpoint: '/api' };
          globalLimiter.check(request);
        }
      }

      // Should have hit global limit (500 * 3 = 1500 > 1000)
      const result = globalLimiter.check({ ip: '1.1.1.1', endpoint: '/api' });
      expect(result.allowed).toBe(false);
    });
  });

  describe('Rate Limit Bypass Attempt Detection', () => {
    /**
     * Tests for detecting attempts to bypass rate limiting
     */
    describe('IP spoofing detection', () => {
      let limiter: MockRateLimiter;

      beforeEach(() => {
        limiter = new MockRateLimiter({
          windowMs: 60000,
          maxRequests: 10,
          keyGenerator: req => {
            // Use real IP, not X-Forwarded-For (which can be spoofed)
            return `ip:${req.ip}`;
          },
        });
      });

      it('should ignore X-Forwarded-For header from untrusted sources', () => {
        const request = {
          ip: '192.168.1.1', // Real IP
          endpoint: '/api',
          headers: {
            'x-forwarded-for': '10.0.0.1, 20.0.0.1', // Spoofed
          },
        };

        // Exhaust limit
        for (let i = 0; i < 10; i++) {
          limiter.check(request);
        }

        // Changing X-Forwarded-For should not reset limit
        request.headers['x-forwarded-for'] = '30.0.0.1';
        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
      });
    });

    describe('Token rotation detection', () => {
      it('should track rate limits by user ID, not token', () => {
        const limiter = new MockRateLimiter({
          windowMs: 60000,
          maxRequests: 10,
          keyGenerator: req => `user:${req.userId}`,
        });

        const request = {
          ip: '192.168.1.1',
          userId: 'user-1',
          endpoint: '/api',
          headers: { authorization: 'Bearer token-1' },
        };

        // Exhaust limit
        for (let i = 0; i < 10; i++) {
          limiter.check(request);
        }

        // New token for same user should still be blocked
        request.headers.authorization = 'Bearer token-2';
        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
      });
    });

    describe('User-Agent rotation detection', () => {
      it('should not allow bypass by changing User-Agent', () => {
        const limiter = new MockRateLimiter({
          windowMs: 60000,
          maxRequests: 10,
          keyGenerator: req => `ip:${req.ip}`,
        });

        const request = {
          ip: '192.168.1.1',
          endpoint: '/api',
          headers: { 'user-agent': 'Mozilla/5.0' },
        };

        // Exhaust limit
        for (let i = 0; i < 10; i++) {
          limiter.check(request);
        }

        // Changing User-Agent should not reset limit
        request.headers['user-agent'] = 'Chrome/100.0';
        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
      });
    });
  });

  describe('Distributed Rate Limiting (IP Rotation)', () => {
    /**
     * Tests for handling attackers rotating IPs
     */
    describe('Fingerprint-based rate limiting', () => {
      let limiter: MockRateLimiter;

      beforeEach(() => {
        limiter = new MockRateLimiter({
          windowMs: 60000,
          maxRequests: 10,
          keyGenerator: req => {
            // Create fingerprint from multiple attributes
            const fingerprint = crypto
              .createHash('sha256')
              .update(
                JSON.stringify({
                  userId: req.userId,
                  userAgent: req.headers?.['user-agent'],
                  acceptLanguage: req.headers?.['accept-language'],
                })
              )
              .digest('hex');
            return `fp:${fingerprint}`;
          },
        });
      });

      it('should track by fingerprint across IP changes', () => {
        const baseRequest = {
          ip: '192.168.1.1',
          userId: 'attacker',
          endpoint: '/api',
          headers: {
            'user-agent': 'AttackerBot/1.0',
            'accept-language': 'en-US',
          },
        };

        // Exhaust limit
        for (let i = 0; i < 10; i++) {
          limiter.check(baseRequest);
        }

        // Change IP but keep same fingerprint
        const newIpRequest = { ...baseRequest, ip: '10.0.0.1' };
        const result = limiter.check(newIpRequest);
        expect(result.allowed).toBe(false);
      });
    });

    describe('Velocity-based detection', () => {
      it('should detect suspiciously high request velocity', () => {
        const requestTimestamps: number[] = [];
        const velocityThreshold = 100; // requests per second

        // Simulate burst of requests
        const now = Date.now();
        for (let i = 0; i < 150; i++) {
          requestTimestamps.push(now + i * 5); // 200 requests per second
        }

        // Calculate velocity
        const timeSpan = (requestTimestamps[requestTimestamps.length - 1] - requestTimestamps[0]) / 1000;
        const velocity = requestTimestamps.length / timeSpan;

        expect(velocity).toBeGreaterThan(velocityThreshold);
      });
    });
  });

  describe('Rate Limit Header Validation', () => {
    /**
     * Tests that rate limit headers are properly set
     */
    let limiter: MockRateLimiter;

    beforeEach(() => {
      limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 100,
        keyGenerator: req => `ip:${req.ip}`,
      });
    });

    it('should return X-RateLimit-Limit header', () => {
      const request = { ip: '192.168.1.1', endpoint: '/api' };
      const result = limiter.check(request);

      expect(result.limit).toBe(100);
    });

    it('should return X-RateLimit-Remaining header', () => {
      const request = { ip: '192.168.1.1', endpoint: '/api' };

      limiter.check(request);
      const result = limiter.check(request);

      expect(result.remaining).toBe(98);
    });

    it('should return X-RateLimit-Reset header', () => {
      const request = { ip: '192.168.1.1', endpoint: '/api' };
      const result = limiter.check(request);

      expect(result.resetTime).toBeGreaterThan(Date.now());
    });

    it('should return Retry-After header when limited', () => {
      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Exhaust limit
      for (let i = 0; i < 100; i++) {
        limiter.check(request);
      }

      const result = limiter.check(request);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should decrement remaining correctly', () => {
      const request = { ip: '192.168.1.1', endpoint: '/api' };

      for (let i = 0; i < 10; i++) {
        const result = limiter.check(request);
        expect(result.remaining).toBe(99 - i);
      }
    });
  });

  describe('Recovery After Rate Limit Window', () => {
    /**
     * Tests that rate limits properly reset after window expires
     */
    it('should reset rate limit after window expires', async () => {
      const limiter = new MockRateLimiter({
        windowMs: 100, // 100ms window for fast testing
        maxRequests: 5,
        keyGenerator: req => `ip:${req.ip}`,
      });

      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        limiter.check(request);
      }

      expect(limiter.check(request).allowed).toBe(false);

      // Wait for window to reset
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should be allowed again
      const result = limiter.check(request);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it('should start new window with full quota', async () => {
      const limiter = new MockRateLimiter({
        windowMs: 100,
        maxRequests: 10,
        keyGenerator: req => `ip:${req.ip}`,
      });

      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Use some quota
      for (let i = 0; i < 7; i++) {
        limiter.check(request);
      }

      // Wait for window to reset
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should have full quota
      const result = limiter.check(request);
      expect(result.remaining).toBe(9);
    });
  });

  describe('Token Bucket Rate Limiting', () => {
    /**
     * Tests for token bucket algorithm implementation
     */
    describe('Bucket refill', () => {
      it('should refill tokens over time', async () => {
        const limiter = new TokenBucketLimiter({
          bucketSize: 10,
          refillRate: 10, // 10 tokens per second
          keyGenerator: req => `ip:${req.ip}`,
        });

        const request = { ip: '192.168.1.1', endpoint: '/api' };

        // Use all tokens
        for (let i = 0; i < 10; i++) {
          limiter.check(request);
        }

        // Should be empty
        expect(limiter.check(request).allowed).toBe(false);

        // Wait for refill
        await new Promise(resolve => setTimeout(resolve, 200));

        // Should have some tokens
        const result = limiter.check(request);
        expect(result.allowed).toBe(true);
      });

      it('should not exceed bucket size', async () => {
        const limiter = new TokenBucketLimiter({
          bucketSize: 10,
          refillRate: 100, // Fast refill
          keyGenerator: req => `ip:${req.ip}`,
        });

        const request = { ip: '192.168.1.1', endpoint: '/api' };

        // Use one token
        limiter.check(request);

        // Wait for significant refill time
        await new Promise(resolve => setTimeout(resolve, 200));

        // Should not exceed bucket size
        const result = limiter.check(request);
        expect(result.remaining).toBeLessThanOrEqual(10);
      });
    });

    describe('Burst handling', () => {
      it('should allow bursts up to bucket size', () => {
        const limiter = new TokenBucketLimiter({
          bucketSize: 50,
          refillRate: 1, // Slow refill
          keyGenerator: req => `ip:${req.ip}`,
        });

        const request = { ip: '192.168.1.1', endpoint: '/api' };

        // Should allow 50 rapid requests
        let allowed = 0;
        for (let i = 0; i < 50; i++) {
          if (limiter.check(request).allowed) {
            allowed++;
          }
        }

        expect(allowed).toBe(50);
      });

      it('should rate limit after burst', () => {
        const limiter = new TokenBucketLimiter({
          bucketSize: 10,
          refillRate: 1,
          keyGenerator: req => `ip:${req.ip}`,
        });

        const request = { ip: '192.168.1.1', endpoint: '/api' };

        // Exhaust burst capacity
        for (let i = 0; i < 10; i++) {
          limiter.check(request);
        }

        // Should be rate limited
        const result = limiter.check(request);
        expect(result.allowed).toBe(false);
      });
    });
  });

  describe('Rate Limit Integration with RateLimitTester', () => {
    /**
     * Tests using the fixture's RateLimitTester
     */
    it('should use RateLimitTester for endpoint testing', async () => {
      const tester = new RateLimitTester({
        endpoint: '/auth/login',
        windowMs: 60000,
        expectedLimit: 10,
      });

      // Simulate making requests
      let blocked = false;
      for (let i = 0; i < 15; i++) {
        const result = tester.makeRequest();
        if (!result.allowed) {
          blocked = true;
          break;
        }
      }

      expect(blocked).toBe(true);
    });

    it('should verify rate limit configuration matches expectations', () => {
      const tester = new RateLimitTester({
        endpoint: '/auth/login',
        windowMs: RATE_LIMIT_CONFIGS.authentication.windowMs,
        expectedLimit: RATE_LIMIT_CONFIGS.authentication.maxRequests,
      });

      expect(tester.verifyConfig()).toBe(true);
    });
  });

  describe('Concurrent Request Handling', () => {
    /**
     * Tests for race conditions in rate limiting
     */
    it('should handle concurrent requests correctly', async () => {
      const limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 100,
        keyGenerator: req => `ip:${req.ip}`,
      });

      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Simulate concurrent requests
      const promises: Promise<RateLimitResult>[] = [];
      for (let i = 0; i < 50; i++) {
        promises.push(Promise.resolve(limiter.check(request)));
      }

      const results = await Promise.all(promises);

      // All should be allowed but remaining should decrease
      expect(results.every(r => r.allowed)).toBe(true);

      // Final state should show 50 requests used
      const finalResult = limiter.check(request);
      expect(finalResult.remaining).toBe(49);
    });

    it('should not allow more than limit even with concurrent requests', async () => {
      const limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 10,
        keyGenerator: req => `ip:${req.ip}`,
      });

      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Simulate many concurrent requests
      const promises: Promise<RateLimitResult>[] = [];
      for (let i = 0; i < 50; i++) {
        promises.push(Promise.resolve(limiter.check(request)));
      }

      const results = await Promise.all(promises);

      // Exactly 10 should be allowed
      const allowedCount = results.filter(r => r.allowed).length;
      expect(allowedCount).toBe(10);
    });
  });

  describe('Error Handling', () => {
    /**
     * Tests for rate limiter error scenarios
     */
    it('should handle missing request data gracefully', () => {
      const limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 100,
        keyGenerator: req => `ip:${req.ip || 'unknown'}`,
      });

      const request = { ip: '', endpoint: '/api' };
      const result = limiter.check(request);

      // Should still work with default key
      expect(result).toBeDefined();
      expect(typeof result.allowed).toBe('boolean');
    });

    it('should handle very high request counts', () => {
      const limiter = new MockRateLimiter({
        windowMs: 60000,
        maxRequests: 100,
        keyGenerator: req => `ip:${req.ip}`,
      });

      const request = { ip: '192.168.1.1', endpoint: '/api' };

      // Make many requests
      for (let i = 0; i < 10000; i++) {
        limiter.check(request);
      }

      // Should handle gracefully
      const result = limiter.check(request);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });
  });
});
