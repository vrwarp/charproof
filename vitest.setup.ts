import { vi } from 'vitest';
import "fake-indexeddb/auto";

// Robust in-memory localStorage mock
const store = new Map<string, string>();
const localStorageMock = {
  getItem: vi.fn((key: string): string | null => {
    return store.has(key) ? store.get(key)! : null;
  }),
  setItem: vi.fn((key: string, value: string): void => {
    store.set(key, String(value));
  }),
  removeItem: vi.fn((key: string): void => {
    store.delete(key);
  }),
  clear: vi.fn((): void => {
    store.clear();
  }),
  key: vi.fn((index: number): string | null => {
    const keys = Array.from(store.keys());
    return keys[index] || null;
  }),
  get length() {
    return store.size;
  }
};

Object.defineProperty(globalThis, 'localStorage', {
  value: localStorageMock,
  writable: true,
  configurable: true
});
