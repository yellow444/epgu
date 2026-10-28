const FALLBACK_FILENAME = 'downloaded_file.zip';
const FORBIDDEN_FILENAME_CHARACTERS = new Set('<>:"/\\|?*');

const headerValue = (headers, name) => {
  if (!headers) return '';
  if (typeof headers.get === 'function') return headers.get(name) || '';
  return headers[name] || headers[name.toLowerCase()] || '';
};

const stripQuotes = (value) => {
  const trimmed = String(value || '').trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
};

const safeFilename = (value, fallback) => {
  const normalized = Array.from(String(value || ''))
    .map((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint <= 31 ||
        codePoint === 127 ||
        FORBIDDEN_FILENAME_CHARACTERS.has(character)
        ? '_'
        : character;
    })
    .join('')
    .trim();
  return normalized || fallback;
};

/** Parse Content-Disposition, preferring the UTF-8 RFC 5987 filename*. */
export const contentDispositionFilename = (
  disposition,
  fallback = FALLBACK_FILENAME
) => {
  if (typeof disposition !== 'string') return fallback;

  const extended = disposition.match(/filename\*\s*=\s*([^;]+)/i);
  if (extended) {
    const raw = stripQuotes(extended[1]);
    const encoded = raw.match(/^[^']*'[^']*'(.*)$/)?.[1] ?? raw;
    try {
      return safeFilename(decodeURIComponent(encoded), fallback);
    } catch (error) {
      // Fall through to the ASCII filename when an upstream header is malformed.
    }
  }

  const regular = disposition.match(
    /filename(?!\*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))/i
  );
  const value = regular?.[1]?.replace(/\\(["\\])/g, '$1') ?? regular?.[2];
  return safeFilename(value, fallback);
};

/** Trigger a browser download and always release the temporary blob URL. */
export const saveBlobResponse = (
  response,
  {
    documentObject = document,
    urlObject = window.URL,
    fallbackFilename = FALLBACK_FILENAME,
  } = {}
) => {
  const disposition = headerValue(response?.headers, 'content-disposition');
  const filename = contentDispositionFilename(disposition, fallbackFilename);
  const blob = response?.data instanceof Blob ? response.data : new Blob([response?.data]);
  const blobUrl = urlObject.createObjectURL(blob);
  const link = documentObject.createElement('a');
  link.href = blobUrl;
  link.setAttribute('download', filename);
  documentObject.body.appendChild(link);
  try {
    link.click();
  } finally {
    link.remove();
    urlObject.revokeObjectURL(blobUrl);
  }
  return filename;
};

/** Await every response file so failures propagate to the caller's catch block. */
export const downloadFilesSequentially = async (files, download) => {
  for (const file of files) {
    await download(file);
  }
};
