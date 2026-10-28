const DECIMAL_ORDER_ID = /^[1-9]\d*$/;

/** Preserve server identifiers as strings and reject unsafe numeric coercion. */
export const exactOrderId = (value) => {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value > 0 ? String(value) : '';
  }
  return typeof value === 'string' ? value.trim() : '';
};

export const isValidOrderId = (value) => DECIMAL_ORDER_ID.test(exactOrderId(value));

/** Construct a route only from a validated ID so input cannot select another endpoint. */
export const orderRoute = (value, suffix = '') => {
  const id = exactOrderId(value);
  if (!DECIMAL_ORDER_ID.test(id)) {
    throw new TypeError('Order ID must be a positive decimal string.');
  }
  return `/order/${encodeURIComponent(id)}${suffix}`;
};
