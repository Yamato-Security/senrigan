import "@testing-library/jest-dom";
import { server } from "./mocks/server";

// Start MSW server before all tests
beforeAll(() => server.listen({ onUnhandledRequest: "warn" }));

// Reset handlers to defaults after each test
afterEach(() => server.resetHandlers());

// Close MSW server after all tests complete
afterAll(() => server.close());

// Polyfill ResizeObserver (required by React Flow)
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Polyfill DOMMatrixReadOnly (required by React Flow internals)
global.DOMMatrixReadOnly = class DOMMatrixReadOnly {
  m11 = 1; m12 = 0; m13 = 0; m14 = 0;
  m21 = 0; m22 = 1; m23 = 0; m24 = 0;
  m31 = 0; m32 = 0; m33 = 1; m34 = 0;
  m41 = 0; m42 = 0; m43 = 0; m44 = 1;
  constructor(_init?: string | number[]) {}
} as unknown as typeof DOMMatrixReadOnly;

