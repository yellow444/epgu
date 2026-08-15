const diagnosticSummary = (value) => {
  if (value === null || value === undefined) return value;
  if (['string', 'number', 'boolean'].includes(typeof value)) return value;

  const summary = {
    type:
      (typeof value.name === 'string' && value.name) ||
      value.constructor?.name ||
      'Error',
  };
  if (typeof value.message === 'string') summary.message = value.message;
  if (typeof value.code === 'string') summary.code = value.code;
  if (Number.isInteger(value.response?.status)) {
    summary.status = value.response.status;
  }
  return summary;
};

/** Log diagnostics without retaining Axios request/config/headers/body objects. */
export const logError = (message, diagnostic) => {
  const args = [String(message)];
  if (diagnostic !== undefined) args.push(diagnosticSummary(diagnostic));
  // eslint-disable-next-line no-console
  console.error(...args);
};

export const sanitizeDiagnostic = diagnosticSummary;
