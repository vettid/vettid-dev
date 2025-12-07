/**
 * HTTP API test client
 * Provides utilities for testing Lambda handlers via HTTP API
 */

export interface TestClientConfig {
  baseUrl: string;
  defaultHeaders?: Record<string, string>;
}

export interface TestResponse<T = any> {
  status: number;
  headers: Record<string, string>;
  body: T;
  raw: string;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string>;
  timeout?: number;
}

export class TestClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;

  constructor(config: TestClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      ...config.defaultHeaders
    };
  }

  /**
   * Set authorization header
   */
  setAuthToken(token: string): void {
    this.defaultHeaders['Authorization'] = `Bearer ${token}`;
  }

  /**
   * Clear authorization header
   */
  clearAuthToken(): void {
    delete this.defaultHeaders['Authorization'];
  }

  /**
   * Make GET request
   */
  async get<T = any>(
    path: string,
    options?: RequestOptions
  ): Promise<TestResponse<T>> {
    return this.request<T>('GET', path, undefined, options);
  }

  /**
   * Make POST request
   */
  async post<T = any>(
    path: string,
    body?: any,
    options?: RequestOptions
  ): Promise<TestResponse<T>> {
    return this.request<T>('POST', path, body, options);
  }

  /**
   * Make PUT request
   */
  async put<T = any>(
    path: string,
    body?: any,
    options?: RequestOptions
  ): Promise<TestResponse<T>> {
    return this.request<T>('PUT', path, body, options);
  }

  /**
   * Make DELETE request
   */
  async delete<T = any>(
    path: string,
    options?: RequestOptions
  ): Promise<TestResponse<T>> {
    return this.request<T>('DELETE', path, undefined, options);
  }

  /**
   * Make generic request
   */
  private async request<T>(
    method: string,
    path: string,
    body?: any,
    options?: RequestOptions
  ): Promise<TestResponse<T>> {
    const url = new URL(path, this.baseUrl);

    // Add query parameters
    if (options?.query) {
      Object.entries(options.query).forEach(([key, value]) => {
        url.searchParams.append(key, value);
      });
    }

    const headers = {
      ...this.defaultHeaders,
      ...options?.headers
    };

    const fetchOptions: RequestInit = {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    };

    const controller = new AbortController();
    const timeout = options?.timeout || 30000;
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url.toString(), {
        ...fetchOptions,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      const raw = await response.text();
      let parsedBody: T;

      try {
        parsedBody = JSON.parse(raw);
      } catch {
        parsedBody = raw as unknown as T;
      }

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      return {
        status: response.status,
        headers: responseHeaders,
        body: parsedBody,
        raw
      };
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
}

/**
 * Create test client with default configuration
 */
export function createTestClient(baseUrl?: string): TestClient {
  return new TestClient({
    baseUrl: baseUrl || process.env.API_URL || 'http://localhost:3000'
  });
}

/**
 * Assert response status
 */
export function expectStatus(response: TestResponse, expectedStatus: number): void {
  if (response.status !== expectedStatus) {
    throw new Error(
      `Expected status ${expectedStatus} but got ${response.status}. Body: ${response.raw}`
    );
  }
}

/**
 * Assert response has required fields
 */
export function expectFields(body: any, fields: string[]): void {
  for (const field of fields) {
    if (!(field in body)) {
      throw new Error(`Expected field "${field}" in response body`);
    }
  }
}
