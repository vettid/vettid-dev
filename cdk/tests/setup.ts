/**
 * Jest global setup file
 * Runs before all tests
 */

// Export to make this a module
export {};

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.AWS_REGION = 'us-east-1';

// Increase timeout for integration tests
jest.setTimeout(30000);

// Mock console.error to catch unhandled errors in tests
const originalConsoleError = console.error;
console.error = (...args: any[]) => {
  // Suppress known warnings during tests
  const message = args[0]?.toString() || '';
  if (message.includes('Warning:')) {
    return;
  }
  originalConsoleError.apply(console, args);
};

// Global test utilities
declare global {
  namespace NodeJS {
    interface Global {
      testUtils: {
        generateUUID: () => string;
        sleep: (ms: number) => Promise<void>;
      };
    }
  }
}

// Add global test utilities
(global as any).testUtils = {
  generateUUID: () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  },
  sleep: (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
};

// Clean up after all tests
afterAll(async () => {
  // Add any global cleanup here
});
