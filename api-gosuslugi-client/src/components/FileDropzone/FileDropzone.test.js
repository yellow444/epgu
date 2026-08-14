import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import FileDropzone from './FileDropzone';

test('remove and clear notify the persistence owner', async () => {
  const first = new File(['a'], 'first.pdf', { type: 'application/pdf' });
  const second = new File(['b'], 'second.pdf', { type: 'application/pdf' });
  const setFiles = jest.fn();
  const onRemove = jest.fn().mockResolvedValue(undefined);
  const onClear = jest.fn().mockResolvedValue(undefined);

  const { rerender } = render(
    <FileDropzone
      files={[first, second]}
      setFiles={setFiles}
      onRemove={onRemove}
      onClear={onClear}
    />
  );

  fireEvent.click(screen.getAllByRole('button')[1]);
  await waitFor(() => expect(onRemove).toHaveBeenCalledWith(first));
  expect(setFiles).toHaveBeenCalledWith([second]);

  rerender(
    <FileDropzone
      files={[second]}
      setFiles={setFiles}
      onRemove={onRemove}
      onClear={onClear}
    />
  );
  fireEvent.click(screen.getByRole('button', { name: /Очистить все/ }));
  await waitFor(() => expect(onClear).toHaveBeenCalledTimes(1));
  expect(setFiles).toHaveBeenCalledWith([]);
});
