import {
  contentDispositionFilename,
  downloadFilesSequentially,
  saveBlobResponse,
} from './downloads';

describe('response downloads', () => {
  test('prefers and decodes RFC 5987 filename* over the ASCII fallback', () => {
    expect(
      contentDispositionFilename(
        "attachment; filename=\"download\"; filename*=UTF-8''%D0%BE%D1%82%D0%B2%D0%B5%D1%82.zip"
      )
    ).toBe('ответ.zip');
  });

  test('falls back to filename when filename* has invalid percent encoding', () => {
    expect(
      contentDispositionFilename(
        "attachment; filename=\"answer.zip\"; filename*=UTF-8''bad%ZZname"
      )
    ).toBe('answer.zip');
  });

  test('clicks the link and always revokes the temporary blob URL', () => {
    const link = {
      click: jest.fn(),
      remove: jest.fn(),
      setAttribute: jest.fn(),
    };
    const documentObject = {
      body: { appendChild: jest.fn() },
      createElement: jest.fn(() => link),
    };
    const urlObject = {
      createObjectURL: jest.fn(() => 'blob:test'),
      revokeObjectURL: jest.fn(),
    };

    const filename = saveBlobResponse(
      {
        data: new Blob(['result']),
        headers: {
          'content-disposition':
            "attachment; filename=\"download\"; filename*=UTF-8''result.zip",
        },
      },
      { documentObject, urlObject }
    );

    expect(filename).toBe('result.zip');
    expect(link.setAttribute).toHaveBeenCalledWith('download', 'result.zip');
    expect(link.click).toHaveBeenCalledTimes(1);
    expect(link.remove).toHaveBeenCalledTimes(1);
    expect(urlObject.revokeObjectURL).toHaveBeenCalledWith('blob:test');
  });

  test('awaits downloads and propagates a response failure', async () => {
    const first = {};
    const failure = new Error('download failed');
    const download = jest
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(failure);

    await expect(
      downloadFilesSequentially([first, {}], download)
    ).rejects.toBe(failure);
    expect(download).toHaveBeenNthCalledWith(1, first);
    expect(download).toHaveBeenCalledTimes(2);
  });
});
