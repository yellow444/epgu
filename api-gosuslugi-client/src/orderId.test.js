import { exactOrderId, isValidOrderId, orderRoute } from './orderId';

describe('Order ID routing', () => {
  test('keeps an identifier above Number.MAX_SAFE_INTEGER exact', () => {
    const id = '9007199254740993';
    expect(exactOrderId(id)).toBe(id);
    expect(isValidOrderId(id)).toBe(true);
    expect(orderRoute(id)).toBe('/order/9007199254740993');
  });

  test.each(['', '0', '01', '123/cancel', '12 3', '-1'])(
    'rejects unsafe or non-decimal input %p',
    (id) => {
      expect(isValidOrderId(id)).toBe(false);
      expect(() => orderRoute(id)).toThrow('positive decimal string');
    }
  );

  test('rejects an already-rounded unsafe JavaScript number', () => {
    expect(exactOrderId(Number.MAX_SAFE_INTEGER + 1)).toBe('');
    expect(isValidOrderId(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
  });
});
