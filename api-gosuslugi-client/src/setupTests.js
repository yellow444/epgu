// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';
import 'fake-indexeddb/auto';

class ResizeObserverMock {
  observe() {}

  unobserve() {}

  disconnect() {}
}

global.ResizeObserver = ResizeObserverMock;

// jsdom не реализует MessageChannel, а @rc-component/select планирует через него
// отложенные задачи. Без заглушки падает любой тест, рендерящий Select.
class MessagePortMock {
  constructor() {
    this.onmessage = null;
    this.peer = null;
  }

  postMessage(data) {
    const { peer } = this;
    if (peer && typeof peer.onmessage === 'function') {
      setTimeout(() => peer.onmessage({ data }), 0);
    }
  }

  start() {}

  close() {}
}

class MessageChannelMock {
  constructor() {
    this.port1 = new MessagePortMock();
    this.port2 = new MessagePortMock();
    this.port1.peer = this.port2;
    this.port2.peer = this.port1;
  }
}

global.MessageChannel = MessageChannelMock;

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});
