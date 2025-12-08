/**
 * Integration Tests: List Handlers Registry API
 *
 * Tests the handler registry listing endpoint:
 * - List available handlers
 * - Filter by category
 * - Pagination
 * - Version information
 * - Installation status
 *
 * @see lambda/handlers/registry/listHandlers.ts (pending implementation)
 */

import * as crypto from 'crypto';
import {
  createMockHandlerPackage,
  createMockManifest,
  HandlerManifest,
} from '../../fixtures/handlers/mockHandler';

// ============================================
// Types
// ============================================

interface HandlerListItem {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  category: string;
  installed: boolean;
  installed_version?: string;
  download_url?: string;
  icon_url?: string;
  rating?: number;
  install_count?: number;
}

interface ListHandlersRequest {
  category?: string;
  search?: string;
  page?: number;
  page_size?: number;
  sort_by?: 'name' | 'rating' | 'installs' | 'updated';
  sort_order?: 'asc' | 'desc';
}

interface ListHandlersResponse {
  handlers: HandlerListItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// ============================================
// Mock Registry Service
// ============================================

class MockRegistryService {
  private handlers: Map<string, HandlerListItem> = new Map();
  private installedHandlers: Map<string, Map<string, string>> = new Map(); // user_id -> (handler_id -> version)

  private defaultPageSize = 20;
  private maxPageSize = 100;

  /**
   * Register a handler in the registry
   */
  registerHandler(manifest: HandlerManifest, options?: {
    rating?: number;
    install_count?: number;
    icon_url?: string;
  }): void {
    this.handlers.set(manifest.id, {
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      description: manifest.description,
      author: manifest.author,
      category: manifest.category,
      installed: false,
      download_url: `https://registry.vettid.dev/handlers/${manifest.id}/${manifest.version}`,
      icon_url: options?.icon_url,
      rating: options?.rating,
      install_count: options?.install_count,
    });
  }

  /**
   * Mark handler as installed for user
   */
  installHandler(userId: string, handlerId: string, version: string): void {
    let userInstalls = this.installedHandlers.get(userId);
    if (!userInstalls) {
      userInstalls = new Map();
      this.installedHandlers.set(userId, userInstalls);
    }
    userInstalls.set(handlerId, version);
  }

  /**
   * List handlers
   */
  listHandlers(userId: string, request: ListHandlersRequest = {}): ListHandlersResponse {
    let handlers = Array.from(this.handlers.values());

    // Filter by category
    if (request.category) {
      handlers = handlers.filter(h => h.category === request.category);
    }

    // Filter by search term
    if (request.search) {
      const searchLower = request.search.toLowerCase();
      handlers = handlers.filter(h =>
        h.name.toLowerCase().includes(searchLower) ||
        h.description.toLowerCase().includes(searchLower)
      );
    }

    // Sort
    const sortBy = request.sort_by || 'name';
    const sortOrder = request.sort_order || 'asc';
    handlers.sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'rating':
          comparison = (a.rating || 0) - (b.rating || 0);
          break;
        case 'installs':
          comparison = (a.install_count || 0) - (b.install_count || 0);
          break;
        case 'updated':
          comparison = a.version.localeCompare(b.version);
          break;
      }
      return sortOrder === 'desc' ? -comparison : comparison;
    });

    // Get user's installed handlers
    const userInstalls = this.installedHandlers.get(userId) || new Map();

    // Add installation status
    handlers = handlers.map(h => ({
      ...h,
      installed: userInstalls.has(h.id),
      installed_version: userInstalls.get(h.id),
    }));

    // Pagination
    const total = handlers.length;
    const pageSize = Math.min(request.page_size || this.defaultPageSize, this.maxPageSize);
    const page = request.page || 1;
    const totalPages = Math.ceil(total / pageSize);

    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    const paginatedHandlers = handlers.slice(start, end);

    return {
      handlers: paginatedHandlers,
      total,
      page,
      page_size: pageSize,
      total_pages: totalPages,
    };
  }

  /**
   * Get handler by ID
   */
  getHandler(handlerId: string): HandlerListItem | undefined {
    return this.handlers.get(handlerId);
  }

  /**
   * Get handler count
   */
  getHandlerCount(): number {
    return this.handlers.size;
  }

  /**
   * Clear all state
   */
  clear(): void {
    this.handlers.clear();
    this.installedHandlers.clear();
  }
}

// ============================================
// Tests
// ============================================

describe('List Handlers', () => {
  let registry: MockRegistryService;
  const testUserId = 'user-list-123';

  beforeEach(() => {
    registry = new MockRegistryService();

    // Populate with sample handlers
    registry.registerHandler(createMockManifest({
      id: 'messaging.send-text',
      name: 'Send Text Message',
      category: 'messaging',
      description: 'Send text messages to connections',
    }), { rating: 4.5, install_count: 1000 });

    registry.registerHandler(createMockManifest({
      id: 'messaging.send-media',
      name: 'Send Media',
      category: 'messaging',
      description: 'Send images and files to connections',
    }), { rating: 4.2, install_count: 800 });

    registry.registerHandler(createMockManifest({
      id: 'profile.update',
      name: 'Update Profile',
      category: 'profile',
      description: 'Update your profile information',
    }), { rating: 4.8, install_count: 1500 });

    registry.registerHandler(createMockManifest({
      id: 'connections.invite',
      name: 'Connection Invite',
      category: 'connections',
      description: 'Create and manage connection invites',
    }), { rating: 4.3, install_count: 900 });

    registry.registerHandler(createMockManifest({
      id: 'finance.btc-wallet',
      name: 'Bitcoin Wallet',
      category: 'finance',
      description: 'Manage Bitcoin transactions',
    }), { rating: 4.0, install_count: 500 });
  });

  afterEach(() => {
    registry.clear();
  });

  it('should return available handlers', () => {
    const result = registry.listHandlers(testUserId);

    expect(result.handlers.length).toBeGreaterThan(0);
    expect(result.total).toBe(5);
  });

  it('should filter by category', () => {
    const result = registry.listHandlers(testUserId, {
      category: 'messaging',
    });

    expect(result.handlers).toHaveLength(2);
    expect(result.handlers.every(h => h.category === 'messaging')).toBe(true);
  });

  it('should paginate results', () => {
    const page1 = registry.listHandlers(testUserId, { page: 1, page_size: 2 });
    const page2 = registry.listHandlers(testUserId, { page: 2, page_size: 2 });
    const page3 = registry.listHandlers(testUserId, { page: 3, page_size: 2 });

    expect(page1.handlers).toHaveLength(2);
    expect(page2.handlers).toHaveLength(2);
    expect(page3.handlers).toHaveLength(1);
    expect(page1.total_pages).toBe(3);
  });

  it('should include version information', () => {
    const result = registry.listHandlers(testUserId);

    for (const handler of result.handlers) {
      expect(handler.version).toBeDefined();
      expect(handler.version).toMatch(/^\d+\.\d+\.\d+/);
    }
  });

  it('should indicate installed status', () => {
    // Install a handler
    registry.installHandler(testUserId, 'messaging.send-text', '1.0.0');

    const result = registry.listHandlers(testUserId);

    const installedHandler = result.handlers.find(h => h.id === 'messaging.send-text');
    const notInstalledHandler = result.handlers.find(h => h.id === 'profile.update');

    expect(installedHandler?.installed).toBe(true);
    expect(installedHandler?.installed_version).toBe('1.0.0');
    expect(notInstalledHandler?.installed).toBe(false);
  });

  it('should include download URL', () => {
    const result = registry.listHandlers(testUserId);

    for (const handler of result.handlers) {
      expect(handler.download_url).toBeDefined();
      expect(handler.download_url).toContain(handler.id);
    }
  });

  it('should support search by name', () => {
    const result = registry.listHandlers(testUserId, {
      search: 'Bitcoin',
    });

    expect(result.handlers).toHaveLength(1);
    expect(result.handlers[0].name).toContain('Bitcoin');
  });

  it('should support search by description', () => {
    const result = registry.listHandlers(testUserId, {
      search: 'transactions',
    });

    expect(result.handlers).toHaveLength(1);
    expect(result.handlers[0].description).toContain('transactions');
  });

  it('should support case-insensitive search', () => {
    const result = registry.listHandlers(testUserId, {
      search: 'PROFILE',
    });

    expect(result.handlers.length).toBeGreaterThan(0);
  });

  it('should sort by name ascending', () => {
    const result = registry.listHandlers(testUserId, {
      sort_by: 'name',
      sort_order: 'asc',
    });

    const names = result.handlers.map(h => h.name);
    const sorted = [...names].sort((a, b) => a.localeCompare(b));

    expect(names).toEqual(sorted);
  });

  it('should sort by rating descending', () => {
    const result = registry.listHandlers(testUserId, {
      sort_by: 'rating',
      sort_order: 'desc',
    });

    const ratings = result.handlers.map(h => h.rating || 0);
    for (let i = 1; i < ratings.length; i++) {
      expect(ratings[i]).toBeLessThanOrEqual(ratings[i - 1]);
    }
  });

  it('should sort by install count', () => {
    const result = registry.listHandlers(testUserId, {
      sort_by: 'installs',
      sort_order: 'desc',
    });

    const counts = result.handlers.map(h => h.install_count || 0);
    for (let i = 1; i < counts.length; i++) {
      expect(counts[i]).toBeLessThanOrEqual(counts[i - 1]);
    }
  });

  it('should respect max page size', () => {
    // Try to request more than max
    const result = registry.listHandlers(testUserId, {
      page_size: 1000,
    });

    expect(result.page_size).toBeLessThanOrEqual(100);
  });

  it('should return correct pagination metadata', () => {
    const result = registry.listHandlers(testUserId, {
      page: 2,
      page_size: 2,
    });

    expect(result.page).toBe(2);
    expect(result.page_size).toBe(2);
    expect(result.total).toBe(5);
    expect(result.total_pages).toBe(3);
  });

  it('should return empty results for out of range page', () => {
    const result = registry.listHandlers(testUserId, {
      page: 100,
      page_size: 10,
    });

    expect(result.handlers).toHaveLength(0);
    expect(result.page).toBe(100);
  });

  it('should combine filter and pagination', () => {
    const result = registry.listHandlers(testUserId, {
      category: 'messaging',
      page: 1,
      page_size: 1,
    });

    expect(result.handlers).toHaveLength(1);
    expect(result.total).toBe(2);
    expect(result.total_pages).toBe(2);
  });

  it('should include rating and install count', () => {
    const result = registry.listHandlers(testUserId);

    const handler = result.handlers.find(h => h.id === 'profile.update');
    expect(handler?.rating).toBe(4.8);
    expect(handler?.install_count).toBe(1500);
  });

  it('should handle empty registry', () => {
    registry.clear();

    const result = registry.listHandlers(testUserId);

    expect(result.handlers).toHaveLength(0);
    expect(result.total).toBe(0);
    expect(result.total_pages).toBe(0);
  });

  it('should filter by multiple conditions', () => {
    const result = registry.listHandlers(testUserId, {
      category: 'messaging',
      search: 'text',
    });

    expect(result.handlers).toHaveLength(1);
    expect(result.handlers[0].id).toBe('messaging.send-text');
  });
});
